package handler

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/admission"
)

var auditReject struct {
	mu   sync.Mutex
	last time.Time
}

func logAuditReject() {
	auditReject.mu.Lock()
	defer auditReject.mu.Unlock()
	if time.Since(auditReject.last) < time.Minute {
		return
	}
	auditReject.last = time.Now()
	log.Printf("audit-webhook: rejected a request whose token is missing or wrong — " +
		"AUDIT_WEBHOOK_TOKEN is set here, so the kube-apiserver's audit-webhook config " +
		"must carry the same value at the end of its server URL, " +
		"e.g. server: http://<sentinel>/api/admission-events/webhook/<token> " +
		"(see docs/audit-webhook.md); its audit events are NOT being recorded")
}

// admissionWebhook receives K8s audit events from the kube-apiserver audit webhook.
// Only VAP violation events (message contains "ValidatingAdmissionPolicy") are stored.
func admissionWebhook(store *admission.Store, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The token arrives as the webhook URL's last path segment (lifted into
		// X-Audit-Webhook-Token before logging) — the one place a kubeconfig can
		// reliably carry a secret to a plain-HTTP server, because client-go
		// silently refuses to send bearer tokens over http. A bearer token is
		// accepted too, for a Sentinel served over TLS. Compared in constant
		// time: a timing oracle on a secret-guarding check is the classic way to
		// leak it byte by byte.
		if token != "" {
			got := r.Header.Get("X-Audit-Webhook-Token")
			if got == "" {
				got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				// Say what is being dropped and why. The likeliest caller is a
				// kube-apiserver whose audit-webhook config is missing the
				// token — without this line, its events silently stop and the
				// access log shows only a bare 401. Throttled: the apiserver
				// retries batches every few seconds, and one line a minute
				// carries the same information.
				logAuditReject()
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		// This route sits outside the session auth, so it is the one that must
		// not let a caller choose the allocation size. Audit batches are small;
		// 4 MiB is already far above a Metadata-level policy's output.
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		var list struct {
			Items []struct {
				AuditID                  string            `json:"auditID"`
				RequestReceivedTimestamp string            `json:"requestReceivedTimestamp"`
				Annotations              map[string]string `json:"annotations"`
				User                     struct {
					Username string `json:"username"`
				} `json:"user"`
				Verb      string `json:"verb"`
				ObjectRef struct {
					Resource  string `json:"resource"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"objectRef"`
				ResponseStatus struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"responseStatus"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		for _, item := range list.Items {
			t := item.RequestReceivedTimestamp
			if t == "" {
				t = time.Now().UTC().Format(time.RFC3339)
			}

			// Normalize patch → update for display
			verb := item.Verb
			if verb == "patch" {
				verb = "update"
			}

			// Case 1: Deny action — violation in responseStatus.message
			msg := item.ResponseStatus.Message
			if strings.Contains(msg, "ValidatingAdmissionPolicy") {
				policy, binding, violation := admission.ParseVAPMessage(msg)
				store.Add(admission.Event{
					ID:          fmt.Sprintf("%s-deny-%d", item.AuditID, time.Now().UnixNano()),
					Time:        t,
					Namespace:   item.ObjectRef.Namespace,
					Resource:    item.ObjectRef.Resource,
					Name:        item.ObjectRef.Name,
					Operation:   verb,
					Username:    item.User.Username,
					PolicyName:  policy,
					BindingName: binding,
					Message:     violation,
					Severity:    "critical",
					Source:      "audit",
				})
				continue
			}

			// Case 2: Audit action — violation in annotations
			const vapAnnotationKey = "validation.policy.admission.k8s.io/validation_failure"
			if annVal, ok := item.Annotations[vapAnnotationKey]; ok {
				var violations []struct {
					Message         string   `json:"message"`
					Policy          string   `json:"policy"`
					Binding         string   `json:"binding"`
					ExpressionIndex int      `json:"expressionIndex"`
					ValidationActions []string `json:"validationActions"`
				}
				if err := json.Unmarshal([]byte(annVal), &violations); err == nil {
					for i, v := range violations {
						vmsg := v.Message
						store.Add(admission.Event{
							ID:          fmt.Sprintf("%s-audit-%d-%d", item.AuditID, i, time.Now().UnixNano()),
							Time:        t,
							Namespace:   item.ObjectRef.Namespace,
							Resource:    item.ObjectRef.Resource,
							Name:        item.ObjectRef.Name,
							Operation:   verb,
							Username:    item.User.Username,
							PolicyName:  v.Policy,
							BindingName: v.Binding,
							Message:     vmsg,
							Severity:    "warning",
							Source:      "audit",
						})
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

func listAdmissionEvents(store *admission.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	}
}

func streamAdmissionEvents(store *admission.Store) http.HandlerFunc {
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
		// Subscribe first to avoid missing events between List and Subscribe.
		ch, unsub := store.Subscribe()
		defer unsub()

		// Send oldest-first so the frontend's prepend logic results in newest-first display
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
