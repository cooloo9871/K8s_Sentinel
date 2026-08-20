package handler

import (
	"time"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cooloo9871/K8s_Sentinel/internal/admission"
	"github.com/cooloo9871/K8s_Sentinel/internal/alert"
	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
	"github.com/cooloo9871/K8s_Sentinel/internal/rsyslog"
	"github.com/cooloo9871/K8s_Sentinel/internal/security"
)

// Config holds dependencies for all handlers.
type Config struct {
	Store           *k8s.Store
	Users           *auth.UserStore
	Secret          []byte
	Alerts          *alert.Store
	Dispatcher      *alert.Dispatcher
	Rsyslog         *rsyslog.Store
	RsyslogDispatch *rsyslog.Dispatcher
	Admission       *admission.Store
	Security        *security.Store
	Audit           *audit.Store
	// Shared secret for the kube-apiserver audit webhook. When set, the webhook
	// requires it as a bearer token; when empty, the endpoint stays open — the
	// route predates the token and existing apiserver configs carry none.
	AuditWebhookToken string
}

// New builds the HTTP handler tree.
func New(cfg Config) http.Handler {
	r := chi.NewRouter()
	// Five failed logins per source IP a minute, then a brief block; slows brute
	// force without letting an attacker lock a real user out.
	loginLimiter := auth.NewLoginLimiter(5, time.Minute)
	// Before the access logger, so the token never reaches the log.
	r.Use(liftWebhookToken)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Outside the session auth — the caller is the kube-apiserver, which has no
	// session. With AuditWebhookToken set it requires that bearer token instead;
	// left unprotected, anything in the cluster could forge admission events and
	// flood the retention cap until the real ones are evicted.
	r.Post(webhookPath, admissionWebhook(cfg.Admission, cfg.AuditWebhookToken))

	// Public auth
	r.Post("/api/auth/login", loginHandler(cfg.Users, cfg.Secret, loginLimiter, cfg.Audit))
	r.Post("/api/auth/logout", logoutHandler(cfg.Users, cfg.Secret))

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(cfg.Secret, cfg.Users))
		// A user who must change their password can reach only /me and their own
		// password change until they do.
		r.Use(mustChangeGate(cfg.Users))

		// Viewer + Admin (read-only)
		r.Get("/api/auth/me", meHandler(cfg.Users))
		r.Get("/api/policies", listPolicies(cfg.Store))
		r.Post("/api/policies/preview", previewPolicy)
		r.Get("/api/policies/{name}", getPolicy(cfg.Store))
		r.Get("/api/namespaces", listNamespaces(cfg.Store))
		r.Get("/api/mode", getMode(cfg.Store))
		r.Get("/api/events/stream", streamTetragonEvents(cfg.Store))
		r.Get("/api/discovery/profiles", getDiscoveryProfiles(cfg.Store))
		r.Get("/api/pods/{namespace}/{pod}/labels", getPodLabels(cfg.Store))
		r.Post("/api/selector-preview", selectorPreview(cfg.Store))
		r.Get("/api/tetragon/agents", getTetragonAgents(cfg.Store))
		r.Get("/api/templates", listTemplates(cfg.Store))
		r.Get("/api/cluster/cidr", getClusterCIDR(cfg.Store))
		// Audited on its own because it lives outside the admin group — a viewer
		// may change their own password, so it cannot sit under adminOnly, but a
		// password change (success or failure) is exactly what the log is for.
		r.With(auditMiddleware(cfg.Audit)).
			Put("/api/users/{username}/password", changePasswordHandler(cfg.Users))
		r.Get("/api/settings/session-ttl", getSessionTTLHandler(cfg.Users))
		r.Get("/api/alerts", listAlerts(cfg.Alerts))
		r.Get("/api/admission-events", listAdmissionEvents(cfg.Admission))
		r.Get("/api/admission-events/stream", streamAdmissionEvents(cfg.Admission))
		r.Get("/api/security-events", listSecurityEvents(cfg.Security))
		r.Get("/api/security-events/stream", streamSecurityEvents(cfg.Security))
		r.Get("/api/security-events/retention", getSecurityRetention(cfg.Security))
		r.Get("/api/admission-events/retention", getAdmissionRetention(cfg.Admission))
		r.Get("/api/network-topology", getNetworkTopology(cfg.Store))
		r.Get("/api/cilium/status", getCiliumStatus(cfg.Store))
		r.Get("/api/cilium/flows/stream", streamCiliumFlows(cfg.Store))
		r.Get("/api/rsyslog", listRsyslog(cfg.Rsyslog))
		r.Get("/api/vap", listVAP(cfg.Store))
		r.Get("/api/vap/{name}", getVAP(cfg.Store))
		r.Get("/api/vap-bindings", listVAPBindings(cfg.Store))
		r.Get("/api/vap-bindings/{name}", getVAPBinding(cfg.Store))
		r.Get("/api/cnp", listCNP(cfg.Store))
		r.Get("/api/cnp/{name}", getCNP(cfg.Store))
		r.Get("/api/quarantine", listQuarantined(cfg.Store))

		// Admin-only (writes)
		r.Group(func(r chi.Router) {
			r.Use(adminOnly)
			// Records every state-changing admin request (skips GET), so the
			// audit log covers new write routes without a per-handler call.
			r.Use(auditMiddleware(cfg.Audit))

			r.Get("/api/audit", listAudit(cfg.Audit))

			r.Post("/api/policies", createPolicy(cfg.Store))
			r.Put("/api/policies/{name}", updatePolicy(cfg.Store))
			r.Put("/api/policies/{name}/mode", setPolicyMode(cfg.Store))
			r.Delete("/api/policies/{name}", deletePolicy(cfg.Store))
			r.Put("/api/mode", setMode(cfg.Store))
			r.Delete("/api/discovery/profiles", clearDiscoveryProfiles(cfg.Store))
			r.Post("/api/templates", createTemplate(cfg.Store))
			r.Put("/api/templates/{id}", updateTemplate(cfg.Store))
			r.Delete("/api/templates/{id}", deleteTemplate(cfg.Store))
			r.Get("/api/users", listUsersHandler(cfg.Users))
			r.Post("/api/users", createUserHandler(cfg.Users))
			r.Delete("/api/users/{username}", deleteUserHandler(cfg.Users))
			r.Put("/api/settings/session-ttl", setSessionTTLHandler(cfg.Users))
			r.Post("/api/alerts/test", testAlert(cfg.Dispatcher))
			r.Post("/api/alerts", createAlert(cfg.Alerts))
			r.Put("/api/alerts/{id}", updateAlert(cfg.Alerts))
			r.Delete("/api/alerts/{id}", deleteAlert(cfg.Alerts))
			r.Post("/api/rsyslog/test", testRsyslog(cfg.RsyslogDispatch))
			r.Post("/api/vap", applyVAP(cfg.Store))
			r.Put("/api/vap/{name}", applyVAP(cfg.Store))
			r.Delete("/api/vap/{name}", deleteVAP(cfg.Store))
			r.Post("/api/vap-bindings", applyVAPBinding(cfg.Store))
			r.Put("/api/vap-bindings/{name}", applyVAPBinding(cfg.Store))
			r.Delete("/api/vap-bindings/{name}", deleteVAPBinding(cfg.Store))
			r.Post("/api/quarantine", quarantinePod(cfg.Store))
			r.Delete("/api/quarantine/{namespace}/{pod}", releasePod(cfg.Store))
			r.Post("/api/cnp", applyCNP(cfg.Store))
			r.Put("/api/cnp/{name}", applyCNP(cfg.Store))
			r.Delete("/api/cnp/{name}", deleteCNP(cfg.Store))
			r.Post("/api/rsyslog", createRsyslog(cfg.Rsyslog))
			r.Put("/api/rsyslog/{id}", updateRsyslog(cfg.Rsyslog))
			r.Delete("/api/rsyslog/{id}", deleteRsyslog(cfg.Rsyslog))
			r.Put("/api/security-events/retention", setSecurityRetention(cfg.Security))
			r.Put("/api/admission-events/retention", setAdmissionRetention(cfg.Admission))
		})
	})

	return r
}

// webhookPath is the audit webhook route; a token may ride as one extra path
// segment.
const webhookPath = "/api/admission-events/webhook"

// liftWebhookToken moves a token sent as the webhook URL's last path segment
// into a header and rewrites the path to the plain route. In the URL because
// that is the one place a kubeconfig can reliably carry a secret to a plain-
// HTTP server — client-go silently refuses to send bearer tokens over http.
// Lifted before the access logger so the secret never reaches the log, and
// before routing so one route serves both spellings.
func liftWebhookToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything after the base path is the token, slashes included — a
		// base64 token carries them, and refusing those turned each delivery
		// into a 404 with the secret printed in the access log on every retry.
		if seg, ok := strings.CutPrefix(r.URL.Path, webhookPath+"/"); ok && seg != "" {
			r.Header.Set("X-Audit-Webhook-Token", seg)
			r.URL.Path = webhookPath
			r.URL.RawPath = ""
			// The access logger prints the raw RequestURI, not the parsed path —
			// left alone, it would print the token this rewrite exists to hide.
			r.RequestURI = webhookPath
			if r.URL.RawQuery != "" {
				r.RequestURI += "?" + r.URL.RawQuery
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
