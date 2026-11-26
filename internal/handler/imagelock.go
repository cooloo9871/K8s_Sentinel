package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func listWorkloads(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace required"})
			return
		}
		if refuseOutside(w, r, namespace) {
			return
		}
		workloads, err := store.ListWorkloads(r.Context(), namespace)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list workloads"})
			return
		}
		writeJSON(w, http.StatusOK, workloads)
	}
}

func createImageLock(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Namespace string `json:"namespace"`
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Mode      string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if req.Namespace == "" || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace and workload required"})
			return
		}
		if req.Mode == "" {
			req.Mode = "Monitoring"
		}
		if req.Mode != "Monitoring" && req.Mode != "Protect" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be Monitoring or Protect"})
			return
		}
		if refuseOutside(w, r, req.Namespace) {
			return
		}
		name := k8s.ImageLockName(req.Name)
		if _, err := store.Get(r.Context(), name, req.Namespace); err == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf(
				"a policy named %q already exists", name)})
			return
		}
		blocksOutside, err := store.CreateImageLock(r.Context(), req.Namespace,
			k8s.Workload{Kind: req.Kind, Name: req.Name}, req.Mode, usernameFromCtx(r))
		switch {
		case errors.Is(err, k8s.ErrWorkloadNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		case errors.Is(err, k8s.ErrNoRunningPod), errors.Is(err, k8s.ErrImageTooLarge):
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusCreated, map[string]any{
				"name": name, "blocksOutside": blocksOutside,
				"inactive": store.AwaitPolicyLoad(r.Context(), name, req.Namespace),
			})
		}
	}
}
