package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"sigs.k8s.io/yaml"

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
		// Renaming is refused above; moving does the same damage sideways, and
		// so does switching the kind. An edit sends the namespace and scope the
		// policy opened from — a manifest saying otherwise would create a copy
		// elsewhere and leave the original in place, while the UI said the edit
		// was saved.
		var manifest struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if yaml.Unmarshal([]byte(body.RawYaml), &manifest) == nil {
			if want := r.URL.Query().Get("namespace"); want != "" {
				if got := manifest.Metadata.Namespace; got != "" && got != want {
					writeError(w, http.StatusBadRequest, fmt.Sprintf(
						"manifest is in namespace %q but this edits %q; moving would leave the original in place. Create a new policy instead", got, want))
					return
				}
			}
			if want := r.URL.Query().Get("scope"); want != "" && manifest.Kind != "" {
				gotCluster := manifest.Kind == "CiliumClusterwideNetworkPolicy"
				if gotCluster != (want == "cluster") {
					writeError(w, http.StatusBadRequest, fmt.Sprintf(
						"manifest kind %s does not match the policy being edited; changing it would leave the original in place. Create a new policy instead", manifest.Kind))
					return
				}
			}
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
