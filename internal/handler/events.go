package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

func streamTetragonEvents(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		// Set SSE headers before any goroutine work to avoid header-after-write issues.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		// Send an initial comment to confirm SSE connection is live.
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		events := make(chan k8s.TetragonEvent, 256)
		errCh := make(chan string, 1) // buffered so goroutine never blocks on send

		go func() {
			// Always close events last so the main loop exits cleanly.
			defer close(events)
			if err := store.StreamTetragonEvents(ctx, events); err != nil && ctx.Err() == nil {
				// ctx.Err() != nil means the client disconnected — don't report as an error.
				select {
				case errCh <- err.Error():
				default:
				}
			}
		}()

		for {
			select {
			case msg := <-errCh:
				// Relay the error as an SSE event so the frontend can show it.
				data, _ := json.Marshal(map[string]string{"error": msg})
				fmt.Fprintf(w, "event: stream-error\ndata: %s\n\n", data)
				flusher.Flush()

			case evt, ok := <-events:
				if !ok {
					// Drain errCh before exiting: the goroutine sends the error
					// then defers close(events), so both may be ready simultaneously.
					// Go's select is non-deterministic — drain ensures the error
					// is not silently dropped when events closes first.
					select {
					case msg := <-errCh:
						data, _ := json.Marshal(map[string]string{"error": msg})
						fmt.Fprintf(w, "event: stream-error\ndata: %s\n\n", data)
						flusher.Flush()
					default:
					}
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
