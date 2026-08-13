package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func listVAP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records, err := store.ListVAP(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, records)
	}
}

func getVAP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		rec, err := store.GetVAP(r.Context(), name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}
}

func applyVAP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RawYAML string `json:"rawYaml"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RawYAML == "" {
			http.Error(w, "rawYaml required", http.StatusBadRequest)
			return
		}
		if !checkManifestName(w, r, body.RawYAML) {
			return
		}
		if err := store.ApplyVAPRaw(r.Context(), body.RawYAML, claimsFromCtx(r).Username); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
	}
}

func deleteVAP(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := store.DeleteVAP(r.Context(), name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func listVAPBindings(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records, err := store.ListVAPBindings(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, records)
	}
}

func getVAPBinding(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		rec, err := store.GetVAPBinding(r.Context(), name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}
}

func applyVAPBinding(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RawYAML string `json:"rawYaml"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RawYAML == "" {
			http.Error(w, "rawYaml required", http.StatusBadRequest)
			return
		}
		if !checkManifestName(w, r, body.RawYAML) {
			return
		}
		if err := store.ApplyVAPBindingRaw(r.Context(), body.RawYAML, claimsFromCtx(r).Username); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
	}
}

func deleteVAPBinding(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := store.DeleteVAPBinding(r.Context(), name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
