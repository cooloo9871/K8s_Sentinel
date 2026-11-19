package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

// getMode says how many tracing policies are enforcing, out of how many.
func getMode(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enforcing, total, err := store.Enforcing(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read policies"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"protect": enforcing, "total": total})
	}
}

// setMode sets every tracing policy to Monitoring. Protect is not accepted
// here: a policy is made to enforce on its own, at /api/policies/{name}/mode.
func setMode(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if req.Mode != "Monitoring" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Only Monitoring can be set for all policies at once. Set Protect on each policy."})
			return
		}
		if err := store.StopEnforcing(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set mode"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
	}
}
