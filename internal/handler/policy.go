package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
	"github.com/cooloo9871/K8s_Sentinel/internal/policy"
)

type createPolicyRequest struct {
	Source  string                  `json:"source"`           // "form" or "yaml"
	Form    *policy.PolicyFormInput `json:"form,omitempty"`
	Action  string                  `json:"action,omitempty"` // "Post" or "Sigkill"
	RawYAML string                  `json:"rawYaml,omitempty"`
}

func listPolicies(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records, err := store.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policies"})
			return
		}
		if records == nil {
			records = []k8s.PolicyRecord{}
		}
		writeJSON(w, http.StatusOK, records)
	}
}

func getPolicy(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		namespace := r.URL.Query().Get("namespace")

		record, err := store.Get(r.Context(), name, namespace)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		writeJSON(w, http.StatusOK, record)
	}
}

func createPolicy(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}

		createdBy := claimsFromCtx(r).Username
		if req.Source == "yaml" {
			if err := store.ApplyRaw(r.Context(), req.RawYAML, createdBy); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
			return
		}

		if req.Form == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "form required"})
			return
		}
		action := req.Action
		if action == "" {
			action = policy.ActionPost
		}
		tp, err := policy.Build(*req.Form, action)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := store.Apply(r.Context(), tp, createdBy); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to apply policy"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
	}
}

func updatePolicy(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}

		// The URL says which policy is being edited; the namespace it opened
		// from rides in the query ("" for a cluster-scoped one). A manifest or
		// form that renames the policy, moves it, or switches it between
		// TracingPolicy and TracingPolicyNamespaced would create a copy and
		// leave the original in place — while the UI said the edit was saved.
		urlName := chi.URLParam(r, "name")
		wantNs, nsPinned := "", false
		if v, ok := r.URL.Query()["namespace"]; ok {
			nsPinned = true
			if len(v) > 0 {
				wantNs = v[0]
			}
		}

		// The editor's name rides along so a policy created before the
		// created-by annotation existed gets adopted on its first save here —
		// the store never overwrites an author that is already recorded.
		editor := usernameFromCtx(r)

		if req.Source == "yaml" {
			if !checkManifestName(w, r, req.RawYAML) {
				return
			}
			var manifest struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			}
			if nsPinned && yaml.Unmarshal([]byte(req.RawYAML), &manifest) == nil {
				if manifest.Kind != "" && (manifest.Kind == "TracingPolicyNamespaced") != (wantNs != "") {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
						"manifest kind %s does not match the policy being edited; changing it would leave the original in place. Create a new policy instead", manifest.Kind)})
					return
				}
				if manifest.Kind == "TracingPolicyNamespaced" && manifest.Metadata.Namespace != wantNs {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
						"manifest is in namespace %q but this edits %q; moving would leave the original in place. Create a new policy instead", manifest.Metadata.Namespace, wantNs)})
					return
				}
			}
			if err := store.ApplyRaw(r.Context(), req.RawYAML, editor); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
			return
		}

		if req.Form == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "form required"})
			return
		}
		if got := strings.TrimSpace(req.Form.Name); got != "" && got != urlName {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
				"form names the policy %q but this edits %q; renaming would leave the original in place. Create a new policy instead", got, urlName)})
			return
		}
		if nsPinned && strings.TrimSpace(req.Form.Namespace) != wantNs {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
				"form puts the policy in namespace %q but this edits %q; moving would leave the original in place. Create a new policy instead", req.Form.Namespace, wantNs)})
			return
		}
		action := req.Action
		if action == "" {
			action = policy.ActionPost
		}
		tp, err := policy.Build(*req.Form, action)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := store.Apply(r.Context(), tp, editor); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to apply policy"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func deletePolicy(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		namespace := r.URL.Query().Get("namespace")

		if err := store.Delete(r.Context(), name, namespace); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete policy"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

func setPolicyMode(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		namespace := r.URL.Query().Get("namespace")

		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if req.Mode != "Monitoring" && req.Mode != "Protect" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be Monitoring or Protect"})
			return
		}
		if err := store.SetPolicyMode(r.Context(), name, namespace, req.Mode); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func previewPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Form   policy.PolicyFormInput `json:"form"`
		Action string                 `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	action := req.Action
	if action == "" {
		action = policy.ActionPost
	}
	tp, err := policy.Build(req.Form, action)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	b, err := yaml.Marshal(tp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(b)})
}

func getClusterCIDR(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.GetClusterCIDR(r.Context()))
	}
}
