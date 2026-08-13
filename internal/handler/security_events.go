package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/security"
)

func listSecurityEvents(store *security.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	}
}

func streamSecurityEvents(store *security.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Subscribe before List to avoid missing events in the gap.
		ch, unsub := store.Subscribe()
		defer unsub()

		// Replay stored events oldest-first so frontend prepend = newest-first.
		initial := store.List()
		for i := len(initial) - 1; i >= 0; i-- {
			data, _ := json.Marshal(initial[i])
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		flusher.Flush()

		for {
			select {
			case <-r.Context().Done():
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(e)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}
