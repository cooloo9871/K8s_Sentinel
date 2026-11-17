package handler

import (
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
	"github.com/go-chi/chi/v5"
)

func getDiscoveryProfiles(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profiles := inScope(scopeOf(r), store.Discovery.All(), func(p *k8s.PodProfile) string { return p.Namespace })
		writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
	}
}

func clearDiscoveryProfiles(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.Discovery.Clear(scopeOf(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func getPodLabels(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := chi.URLParam(r, "namespace")
		pod := chi.URLParam(r, "pod")
		if refuseOutside(w, r, namespace) {
			return
		}
		labels, err := store.GetPodLabels(r.Context(), namespace, pod)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"labels": labels})
	}
}
