package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/brobridge/sentinel/internal/k8s"
)

func streamTetragonEvents(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		events := make(chan k8s.TetragonEvent, 256)

		go func() {
			defer close(events)
			if err := store.StreamTetragonEvents(ctx, events); err != nil {
				// Send error as a special SSE event so the client can display it
				fmt.Fprintf(w, "event: stream-error\ndata: %s\n\n", err.Error())
				flusher.Flush()
			}
		}()

		for {
			select {
			case evt, ok := <-events:
				if !ok {
					return
				}
				data, err := json.Marshal(evt)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()

			case <-r.Context().Done():
				return
			}
		}
	}
}
