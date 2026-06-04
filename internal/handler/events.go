package handler

import (
	"net/http"

	"github.com/brobridge/sentinel/internal/k8s"
)

func listEvents(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := store.ListSecurityEvents(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if events == nil {
			events = []k8s.SecurityEvent{}
		}
		writeJSON(w, http.StatusOK, events)
	}
}
