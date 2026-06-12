package handler

import (
	"net/http"

	"github.com/cooloo9871/sentinel/internal/k8s"
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
