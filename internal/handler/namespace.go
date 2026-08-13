package handler

import (
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func listNamespaces(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		names, err := store.ListNamespaces(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list namespaces"})
			return
		}
		if names == nil {
			names = []string{}
		}
		writeJSON(w, http.StatusOK, names)
	}
}
