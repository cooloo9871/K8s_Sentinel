package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

func getCiliumStatus(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := store.CheckHubbleReady(r.Context())
		writeJSON(w, http.StatusOK, status)
	}
}

func streamCiliumFlows(store *k8s.Store) http.HandlerFunc {
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

		ch, unsub := store.SubscribeCilium()
		defer unsub()
		flusher.Flush()

		for {
			select {
			case <-r.Context().Done():
				return
			case f, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(f)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}
