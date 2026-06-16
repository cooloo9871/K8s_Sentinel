package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cooloo9871/sentinel/internal/admission"
)

// admissionWebhook receives K8s audit events from the kube-apiserver audit webhook.
// Only VAP violation events (message contains "ValidatingAdmissionPolicy") are stored.
func admissionWebhook(store *admission.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
					Operation:   item.Verb,
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
					Policy  string `json:"policy"`
					Binding string `json:"binding"`
					Validation struct {
						Message    string `json:"message"`
						Expression string `json:"expression"`
					} `json:"validation"`
				}
				if err := json.Unmarshal([]byte(annVal), &violations); err == nil {
					for i, v := range violations {
						vmsg := v.Validation.Message
						if vmsg == "" {
							vmsg = fmt.Sprintf("failed expression: %s", v.Validation.Expression)
						}
						store.Add(admission.Event{
							ID:          fmt.Sprintf("%s-audit-%d-%d", item.AuditID, i, time.Now().UnixNano()),
							Time:        t,
							Namespace:   item.ObjectRef.Namespace,
							Resource:    item.ObjectRef.Resource,
							Name:        item.ObjectRef.Name,
							Operation:   item.Verb,
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
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		for _, e := range store.List() {
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		flusher.Flush()

		ch, unsub := store.Subscribe()
		defer unsub()
		for {
			select {
			case <-r.Context().Done():
				return
			case e := <-ch:
				data, _ := json.Marshal(e)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}
