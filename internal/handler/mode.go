package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func getMode(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode, err := store.GetMode(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get mode"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": mode})
	}
}

func setMode(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if req.Mode != "Monitoring" && req.Mode != "Protect" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be Monitoring or Protect"})
			return
		}
		if err := store.SetMode(r.Context(), req.Mode); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set mode"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
	}
}
