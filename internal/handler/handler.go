package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/alert"
	"github.com/cooloo9871/sentinel/internal/auth"
	"github.com/cooloo9871/sentinel/internal/k8s"
	"github.com/cooloo9871/sentinel/internal/rsyslog"
	"github.com/cooloo9871/sentinel/internal/security"
)

// Config holds dependencies for all handlers.
type Config struct {
	Store      *k8s.Store
	Users      *auth.UserStore
	Secret     []byte
	Alerts          *alert.Store
	Dispatcher      *alert.Dispatcher
	Rsyslog         *rsyslog.Store
	RsyslogDispatch *rsyslog.Dispatcher
	Admission       *admission.Store
	Security        *security.Store
}

// New builds the HTTP handler tree.
func New(cfg Config) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public (no auth — kube-apiserver audit webhook)
	r.Post("/api/admission-events/webhook", admissionWebhook(cfg.Admission))

	// Public auth
	r.Post("/api/auth/login", loginHandler(cfg.Users, cfg.Secret))
	r.Post("/api/auth/logout", logoutHandler(cfg.Users))

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(cfg.Secret, cfg.Users))

		// Viewer + Admin (read-only)
		r.Get("/api/auth/me", meHandler())
		r.Get("/api/policies", listPolicies(cfg.Store))
		r.Post("/api/policies/preview", previewPolicy)
		r.Get("/api/policies/{name}", getPolicy(cfg.Store))
		r.Get("/api/namespaces", listNamespaces(cfg.Store))
		r.Get("/api/mode", getMode(cfg.Store))
		r.Get("/api/events/stream", streamTetragonEvents(cfg.Store))
		r.Get("/api/discovery/profiles", getDiscoveryProfiles(cfg.Store))
		r.Get("/api/pods/{namespace}/{pod}/labels", getPodLabels(cfg.Store))
		r.Get("/api/tetragon/agents", getTetragonAgents(cfg.Store))
		r.Get("/api/templates", listTemplates(cfg.Store))
		r.Get("/api/cluster/cidr", getClusterCIDR(cfg.Store))
		r.Put("/api/users/{username}/password", changePasswordHandler(cfg.Users))
		r.Get("/api/settings/session-ttl", getSessionTTLHandler(cfg.Users))
		r.Get("/api/alerts", listAlerts(cfg.Alerts))
		r.Get("/api/admission-events", listAdmissionEvents(cfg.Admission))
		r.Get("/api/admission-events/stream", streamAdmissionEvents(cfg.Admission))
		r.Get("/api/security-events", listSecurityEvents(cfg.Security))
		r.Get("/api/security-events/stream", streamSecurityEvents(cfg.Security))
		r.Get("/api/security-events/retention", getSecurityRetention(cfg.Security))
		r.Get("/api/admission-events/retention", getAdmissionRetention(cfg.Admission))
		r.Get("/api/network-topology", getNetworkTopology(cfg.Security, cfg.Store))
		r.Get("/api/cilium/status", getCiliumStatus(cfg.Store))
		r.Get("/api/cilium/flows/stream", streamCiliumFlows(cfg.Store))
		r.Get("/api/rsyslog", listRsyslog(cfg.Rsyslog))
		r.Get("/api/vap", listVAP(cfg.Store))
		r.Get("/api/vap/{name}", getVAP(cfg.Store))
		r.Get("/api/vap-bindings", listVAPBindings(cfg.Store))
		r.Get("/api/vap-bindings/{name}", getVAPBinding(cfg.Store))

		// Admin-only (writes)
		r.Group(func(r chi.Router) {
			r.Use(adminOnly)

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
			r.Post("/api/rsyslog", createRsyslog(cfg.Rsyslog))
			r.Put("/api/rsyslog/{id}", updateRsyslog(cfg.Rsyslog))
			r.Delete("/api/rsyslog/{id}", deleteRsyslog(cfg.Rsyslog))
			r.Put("/api/security-events/retention", setSecurityRetention(cfg.Security))
			r.Put("/api/admission-events/retention", setAdmissionRetention(cfg.Admission))
		})
	})

	return r
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
