package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/cooloo9871/sentinel/internal/admission"
)

// AdmissionRequest contains the fields we need from the K8s AdmissionRequest.
type AdmissionRequest struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Operation string `json:"operation"`
	Resource  struct {
		Group    string `json:"group"`
		Version  string `json:"version"`
		Resource string `json:"resource"`
	} `json:"resource"`
	Object    json.RawMessage `json:"object"`
	OldObject json.RawMessage `json:"oldObject"`
	UserInfo  struct {
		Username string `json:"username"`
	} `json:"userInfo"`
}

type admissionReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Request    *AdmissionRequest `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}

type status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewAdmissionHandler returns an HTTP handler for the admission webhook endpoint.
func NewAdmissionHandler(evaluator *Evaluator, admStore *admission.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admission", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		var review admissionReview
		if err := json.Unmarshal(body, &review); err != nil || review.Request == nil {
			http.Error(w, "invalid admission review", http.StatusBadRequest)
			return
		}
		req := review.Request

		log.Printf("admission-webhook: request ns=%s name=%s op=%s resource=%s/%s",
			req.Namespace, req.Name, req.Operation, req.Resource.Group, req.Resource.Resource)

		violations, err := evaluator.Evaluate(r.Context(), *req)
		if err != nil {
			log.Printf("admission-webhook: evaluate error: %v", err)
			writeResponse(w, review.APIVersion, req.UID, true, "")
			return
		}

		log.Printf("admission-webhook: %d violation(s)", len(violations))

		if len(violations) == 0 {
			writeResponse(w, review.APIVersion, req.UID, true, "")
			return
		}

		// Build denial message
		msg := violations[0].Message
		if len(violations) > 1 {
			msg = fmt.Sprintf("%s (and %d more)", msg, len(violations)-1)
		}

		// Record in Admission Events store
		for _, v := range violations {
			admStore.AddViolation(admission.Violation{
				Namespace: req.Namespace,
				Name:      req.Name,
				Resource:  req.Resource.Resource,
				Operation: req.Operation,
				Username:  req.UserInfo.Username,
				RuleName:  v.PolicyName,
				Message:   v.Message,
			})
		}

		writeResponse(w, review.APIVersion, req.UID, false, msg)
	})
	return mux
}

func writeResponse(w http.ResponseWriter, apiVersion, uid string, allowed bool, msg string) {
	resp := admissionReview{
		APIVersion: apiVersion,
		Kind:       "AdmissionReview",
		Response: &admissionResponse{
			UID:     uid,
			Allowed: allowed,
		},
	}
	if !allowed && msg != "" {
		resp.Response.Status = &status{Code: 403, Message: msg}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// StartHTTPS starts the HTTPS webhook server on the given address.
func StartHTTPS(ctx context.Context, addr string, bundle *CertBundle, handler http.Handler) error {
	tlsCfg, err := bundle.TLSConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	log.Printf("starting admission webhook on %s", addr)
	return srv.ListenAndServeTLS("", "")
}
