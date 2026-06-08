package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

func getDiscoveryStatus(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enabled := store.IsDiscoveryEnabled(r.Context())
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

func setDiscovery(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		var err error
		if req.Enabled {
			err = store.EnableDiscovery(r.Context())
		} else {
			err = store.DisableDiscovery(r.Context())
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
	}
}

func getPodLabels(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := chi.URLParam(r, "namespace")
		pod := chi.URLParam(r, "pod")
		labels, err := store.GetPodLabels(r.Context(), namespace, pod)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"labels": labels})
	}
}
