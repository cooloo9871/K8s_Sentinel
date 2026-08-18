package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

// selectorPreview answers "which pods would this selector govern" for the
// policy forms, so a selector that matches nothing (or everything) is caught
// before Apply rather than after the policy silently governs the wrong set.
func selectorPreview(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Namespace   string            `json:"namespace"`
			MatchLabels map[string]string `json:"matchLabels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		total, pods, err := store.SelectPods(r.Context(), req.Namespace, req.MatchLabels)
		if errors.Is(err, k8s.ErrInvalidSelector) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"total": total, "pods": pods})
	}
}
