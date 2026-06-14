package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cooloo9871/sentinel/internal/auth"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

// Config holds dependencies for all handlers.
type Config struct {
	Store  *k8s.Store
	Users  *auth.UserStore
	Secret []byte
}

// New builds the HTTP handler tree.
func New(cfg Config) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public
	r.Post("/api/auth/login", loginHandler(cfg.Users, cfg.Secret))
	r.Post("/api/auth/logout", logoutHandler())

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(cfg.Secret))

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
		r.Put("/api/users/{username}/password", changePasswordHandler(cfg.Users))
		r.Get("/api/settings/session-ttl", getSessionTTLHandler(cfg.Users))

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
		})
	})

	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
