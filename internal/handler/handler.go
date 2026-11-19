package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cooloo9871/K8s_Sentinel/internal/admission"
	"github.com/cooloo9871/K8s_Sentinel/internal/alert"
	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
	"github.com/cooloo9871/K8s_Sentinel/internal/registry"
	"github.com/cooloo9871/K8s_Sentinel/internal/rsyslog"
	"github.com/cooloo9871/K8s_Sentinel/internal/security"
	"github.com/cooloo9871/K8s_Sentinel/internal/vulngate"
)

// Config holds dependencies for all handlers.
type Config struct {
	Store           *k8s.Store
	Users           *auth.UserStore
	Roles           *auth.RoleStore
	Secret          []byte
	Alerts          *alert.Store
	Dispatcher      *alert.Dispatcher
	Rsyslog         *rsyslog.Store
	RsyslogDispatch *rsyslog.Dispatcher
	Admission       *admission.Store
	Security        *security.Store
	Audit           *audit.Store
	Registries      *registry.Store
	RegistryScans   *registry.Scanner
	VulnGate        *vulngate.Gate
	// Shared secret for the kube-apiserver audit webhook. When set, the webhook
	// requires it as a bearer token; when empty, the endpoint stays open — the
	// route predates the token and existing apiserver configs carry none.
	AuditWebhookToken string
}

// New builds the HTTP handler tree.
func New(cfg Config) http.Handler {
	r := chi.NewRouter()
	// A tree built without a role store has the two built-in roles.
	if cfg.Roles == nil {
		cfg.Roles = auth.NewRoleStore("")
	}
	// Five failed logins per source IP a minute, then a brief block; slows brute
	// force without letting an attacker lock a real user out.
	loginLimiter := auth.NewLoginLimiter(5, time.Minute)
	// Before the access logger, so the token never reaches the log.
	r.Use(liftWebhookToken)
	r.Use(securityHeaders)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(sameOriginWrites)

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
		r.Use(authMiddleware(cfg.Secret, cfg.Users, cfg.Roles))
		// A user who must change their password can reach only /me and their own
		// password change until they do.
		r.Use(mustChangeGate(cfg.Users))
		// No request a signed-in user sends is anywhere near this size.
		r.Use(middleware.RequestSize(4 << 20))

		// Records every state-changing request it sits in front of (skips GET).
		// It goes after the permission check, so what a role refuses is not
		// written down as something that was attempted on the cluster.
		audited := auditMiddleware(cfg.Audit)
		view, manage := auth.LevelView, auth.LevelManage

		// Open to every signed-in account: who it is, its own password, and what
		// the forms need to offer choices. Each of these answers with what is in
		// the account's namespaces; see scope.go.
		r.Get("/api/auth/me", meHandler(cfg.Users))
		r.With(audited).Put("/api/users/{username}/password", changePasswordHandler(cfg.Users, cfg.Secret))
		r.Get("/api/namespaces", listNamespaces(cfg.Store))
		r.Get("/api/pods/{namespace}/{pod}/labels", getPodLabels(cfg.Store))
		r.Post("/api/selector-preview", selectorPreview(cfg.Store))
		r.Get("/api/cluster/cidr", getClusterCIDR(cfg.Store))

		// Tracing Policy, with the templates and the discovery it is written from.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaTracing, view))
			r.Get("/api/policies", listPolicies(cfg.Store))
			r.Post("/api/policies/preview", previewPolicy)
			r.Get("/api/policies/{name}", getPolicy(cfg.Store))
			r.Get("/api/discovery/profiles", getDiscoveryProfiles(cfg.Store))
			r.Get("/api/templates", listTemplates(cfg.Store))
			r.With(clusterWide).Get("/api/mode", getMode(cfg.Store))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaTracing, manage), audited)
				r.Post("/api/policies", createPolicy(cfg.Store))
				r.Put("/api/policies/{name}", updatePolicy(cfg.Store))
				r.Put("/api/policies/{name}/mode", setPolicyMode(cfg.Store))
				r.Delete("/api/policies/{name}", deletePolicy(cfg.Store))
				r.Delete("/api/discovery/profiles", clearDiscoveryProfiles(cfg.Store))
				r.Group(func(r chi.Router) {
					r.Use(clusterWide)
					r.Put("/api/mode", setMode(cfg.Store))
					r.Post("/api/templates", createTemplate(cfg.Store))
					r.Put("/api/templates/{id}", updateTemplate(cfg.Store))
					r.Delete("/api/templates/{id}", deleteTemplate(cfg.Store))
				})
			})
		})

		// Network Policy and the topology it is read against.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaNetwork, view))
			// The topology is the one view an account limited to namespaces sees
			// whole: a connection has two ends, and the far one is seldom its own.
			r.Get("/api/network-topology", getNetworkTopology(cfg.Store))
			r.Get("/api/cilium/status", getCiliumStatus(cfg.Store))
			r.Get("/api/cilium/flows/stream", streamCiliumFlows(cfg.Store))
			r.Get("/api/cnp", listCNP(cfg.Store))
			r.Get("/api/cnp/{name}", getCNP(cfg.Store))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaNetwork, manage), audited)
				r.Post("/api/cnp", applyCNP(cfg.Store))
				r.Put("/api/cnp/{name}", applyCNP(cfg.Store))
				r.Delete("/api/cnp/{name}", deleteCNP(cfg.Store))
			})
		})

		// Admission policies are the cluster's, but an account limited to
		// namespaces has those marked for them; see vap_scope.go.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaAdmission, view))
			r.Get("/api/vap", listVAP(cfg.Store))
			r.Get("/api/vap/{name}", getVAP(cfg.Store))
			r.Get("/api/vap-bindings", listVAPBindings(cfg.Store))
			r.Get("/api/vap-bindings/{name}", getVAPBinding(cfg.Store))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaAdmission, manage), audited)
				r.Post("/api/vap", applyVAP(cfg.Store, cfg.VulnGate.Refresh))
				r.Put("/api/vap/{name}", applyVAP(cfg.Store, cfg.VulnGate.Refresh))
				r.Delete("/api/vap/{name}", deleteVAP(cfg.Store))
				r.Post("/api/vap-bindings", applyVAPBinding(cfg.Store))
				r.Put("/api/vap-bindings/{name}", applyVAPBinding(cfg.Store))
				r.Delete("/api/vap-bindings/{name}", deleteVAPBinding(cfg.Store))
			})
		})

		// Quarantine.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaQuarantine, view))
			r.Get("/api/quarantine", listQuarantined(cfg.Store))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaQuarantine, manage), audited)
				r.Post("/api/quarantine", quarantinePod(cfg.Store))
				r.Delete("/api/quarantine/{namespace}/{pod}", releasePod(cfg.Store))
			})
		})

		// Events, and whether they are arriving.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaEvents, view))
			r.Get("/api/events/stream", streamTetragonEvents(cfg.Store))
			r.Get("/api/admission-events", listAdmissionEvents(cfg.Admission))
			r.Get("/api/admission-events/stream", streamAdmissionEvents(cfg.Admission))
			r.Get("/api/security-events", listSecurityEvents(cfg.Security))
			r.Get("/api/security-events/stream", streamSecurityEvents(cfg.Security))
			r.Group(func(r chi.Router) {
				r.Use(clusterWide)
				r.Get("/api/tetragon/agents", getTetragonAgents(cfg.Store))
				r.Get("/api/ingestion/health", getIngestionHealth(cfg.Store))
			})
		})
		// How many events are kept and for how long: the event pages say it and
		// the settings page changes it, so either permission reads it.
		r.Group(func(r chi.Router) {
			r.Use(needAny(perm{auth.AreaEvents, view}, perm{auth.AreaSystem, view}))
			r.Get("/api/security-events/retention", getSecurityRetention(cfg.Security))
			r.Get("/api/admission-events/retention", getAdmissionRetention(cfg.Admission))
		})

		// Vulnerabilities, of what runs and of what a registry holds.
		r.Group(func(r chi.Router) {
			r.Use(need(auth.AreaVulnerabilities, view))
			r.Get("/api/vulnerabilities", getVulnerabilities(cfg.Store))
			r.Get("/api/vulnerabilities/{namespace}/{kind}/{name}", getWorkloadVulnerabilities(cfg.Store))
			r.Group(func(r chi.Router) {
				r.Use(clusterWide)
				r.Get("/api/registries", listRegistries(cfg.Registries, cfg.RegistryScans))
				r.Get("/api/registries/{id}/images", registryImages(cfg.Registries, cfg.RegistryScans))
				r.Get("/api/registries/{id}/findings", registryFindings(cfg.RegistryScans))
				r.Group(func(r chi.Router) {
					r.Use(need(auth.AreaVulnerabilities, manage), audited)
					r.Post("/api/registries", createRegistry(cfg.Registries, cfg.RegistryScans))
					r.Post("/api/registries/test", testRegistry(cfg.Registries))
					r.Put("/api/registries/{id}", updateRegistry(cfg.Registries, cfg.RegistryScans))
					r.Delete("/api/registries/{id}", deleteRegistry(cfg.Registries, cfg.RegistryScans))
					r.Post("/api/registries/{id}/scan", scanRegistry(cfg.RegistryScans))
				})
			})
		})

		// Where events are sent. The cluster's.
		r.Group(func(r chi.Router) {
			r.Use(clusterWide, need(auth.AreaNotifications, view))
			r.Get("/api/alerts", listAlerts(cfg.Alerts))
			r.Get("/api/rsyslog", listRsyslog(cfg.Rsyslog))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaNotifications, manage), audited)
				r.Post("/api/alerts/test", testAlert(cfg.Dispatcher))
				r.Post("/api/alerts", createAlert(cfg.Alerts))
				r.Put("/api/alerts/{id}", updateAlert(cfg.Alerts))
				r.Delete("/api/alerts/{id}", deleteAlert(cfg.Alerts))
				r.Post("/api/rsyslog/test", testRsyslog(cfg.RsyslogDispatch))
				r.Post("/api/rsyslog", createRsyslog(cfg.Rsyslog))
				r.Put("/api/rsyslog/{id}", updateRsyslog(cfg.Rsyslog))
				r.Delete("/api/rsyslog/{id}", deleteRsyslog(cfg.Rsyslog))
			})
		})

		// Accounts, roles, the audit log and the settings. The cluster's.
		r.Group(func(r chi.Router) {
			r.Use(clusterWide, need(auth.AreaSystem, view))
			r.Get("/api/audit", listAudit(cfg.Audit))
			r.Get("/api/users", listUsersHandler(cfg.Users))
			r.Get("/api/roles", listRolesHandler(cfg.Roles, cfg.Users))
			r.Get("/api/settings/session-ttl", getSessionTTLHandler(cfg.Users))
			r.Group(func(r chi.Router) {
				r.Use(need(auth.AreaSystem, manage), audited)
				r.Post("/api/users", createUserHandler(cfg.Users, cfg.Roles))
				r.Put("/api/users/{username}/namespaces", setUserNamespacesHandler(cfg.Users))
				r.Put("/api/users/{username}/role", setUserRoleHandler(cfg.Users, cfg.Roles))
				r.Delete("/api/users/{username}", deleteUserHandler(cfg.Users))
				r.Post("/api/roles", createRoleHandler(cfg.Roles))
				r.Put("/api/roles/{name}", updateRoleHandler(cfg.Roles))
				r.Delete("/api/roles/{name}", deleteRoleHandler(cfg.Roles, cfg.Users))
				r.Put("/api/settings/session-ttl", setSessionTTLHandler(cfg.Users))
				r.Put("/api/security-events/retention", setSecurityRetention(cfg.Security))
				r.Put("/api/admission-events/retention", setAdmissionRetention(cfg.Admission))
			})
		})
	})

	return r
}

// securityHeaders sets the browser-side protections on every response. The CSP
// is written for what the SPA actually is: hashed same-origin bundles
// (script-src 'self'), self-hosted woff2 fonts, React inline style attributes
// (the one 'unsafe-inline'), data: URIs for embedded images, and same-origin
// fetch/SSE. Nothing external is ever loaded, so everything else is locked to
// 'self' or off.
// sameOriginWrites refuses a state-changing request that a browser says came
// from another origin. The session cookie is SameSite=Strict, but "site" is
// wider than "origin": another port on localhost during a port-forward, or a
// sibling subdomain, is the same site and its pages would send the cookie.
// A caller that is not a browser sends neither header and is let through; it
// has no cookie to borrow.
func sameOriginWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" && site != "none" {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		} else if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Host != r.Host && u.Host != r.Header.Get("X-Forwarded-Host")) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders is exported for the server, which also puts it in front of
// the SPA: a Content-Security-Policy protects the document it arrives with, so
// one sent only with API responses protected nothing.
func SecurityHeaders(next http.Handler) http.Handler { return securityHeaders(next) }

func securityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}, "; ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
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
