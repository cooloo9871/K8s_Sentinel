package handler

import (
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func getTetragonAgents(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := store.GetTetragonAgents(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
	}
}

// getIngestionHealth reports whether each event source is actually connected
// and delivering, so the console can show a source as blind rather than
// falsely healthy.
func getIngestionHealth(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sources": store.Ingestion().Snapshot()})
	}
}
