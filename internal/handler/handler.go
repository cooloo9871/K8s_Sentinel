package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// Config holds dependencies for all handlers.
type Config struct {
	Store *k8s.Store
}

// New builds the HTTP handler tree.
func New(cfg Config) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/api/policies", listPolicies(cfg.Store))
	r.Post("/api/policies", createPolicy(cfg.Store))
	r.Post("/api/policies/preview", previewPolicy)
	r.Get("/api/policies/{name}", getPolicy(cfg.Store))
	r.Put("/api/policies/{name}", updatePolicy(cfg.Store))
	r.Put("/api/policies/{name}/mode", setPolicyMode(cfg.Store))
	r.Delete("/api/policies/{name}", deletePolicy(cfg.Store))
	r.Get("/api/namespaces", listNamespaces(cfg.Store))
	r.Get("/api/mode", getMode(cfg.Store))
	r.Put("/api/mode", setMode(cfg.Store))
	r.Get("/api/events/stream", streamTetragonEvents(cfg.Store))
	r.Get("/api/discovery", getDiscoveryStatus(cfg.Store))
	r.Put("/api/discovery", setDiscovery(cfg.Store))
	r.Get("/api/pods/{namespace}/{pod}/labels", getPodLabels(cfg.Store))

	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
