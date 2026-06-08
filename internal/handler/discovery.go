package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

func getDiscoveryProfiles(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profiles := store.Discovery.All()
		writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
	}
}

func clearDiscoveryProfiles(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.Discovery.Clear()
		w.WriteHeader(http.StatusNoContent)
	}
}

func getPodLabels(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := chi.URLParam(r, "namespace")
		pod := chi.URLParam(r, "pod")
		labels, err := store.GetPodLabels(r.Context(), namespace, pod)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"labels": labels})
	}
}
