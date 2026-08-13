package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

// listCNP returns all Cilium network policies plus an availability flag so the
// UI can distinguish "no policies yet" from "Cilium CRDs are not installed".
func listCNP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records, err := store.ListCNP(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"available": false,
				"policies":  []k8s.CNPRecord{},
				"message":   err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"available": true,
			"policies":  records,
		})
	}
}

func getCNP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if scope != "cluster" {
			scope = "namespace"
		}
		ns := r.URL.Query().Get("namespace")
		if scope == "namespace" && ns == "" {
			writeError(w, http.StatusBadRequest, "namespace is required for namespaced policies")
			return
		}
		rec, err := store.GetCNP(r.Context(), scope, ns, chi.URLParam(r, "name"))
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}
}

// applyCNP creates or updates from raw YAML; the kind in the manifest decides
// whether the policy is namespaced or cluster-wide.
func applyCNP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RawYaml string `json:"rawYaml"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RawYaml == "" {
			writeError(w, http.StatusBadRequest, "rawYaml is required")
			return
		}
		if !checkManifestName(w, r, body.RawYaml) {
			return
		}
		if err := store.ApplyCNPRaw(r.Context(), body.RawYaml, claimsFromCtx(r).Username); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteCNP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if scope != "cluster" {
			scope = "namespace"
		}
		ns := r.URL.Query().Get("namespace")
		if scope == "namespace" && ns == "" {
			writeError(w, http.StatusBadRequest, "namespace is required for namespaced policies")
			return
		}
		if err := store.DeleteCNP(r.Context(), scope, ns, chi.URLParam(r, "name")); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
