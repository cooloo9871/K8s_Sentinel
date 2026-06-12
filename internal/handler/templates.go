package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

func listTemplates(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"templates": store.Templates.List()})
	}
}

func createTemplate(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var t k8s.CustomTemplate
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if t.ID == "" || t.Name == "" || t.YAML == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, name and yaml are required"})
			return
		}
		store.Templates.Add(t)
		writeJSON(w, http.StatusCreated, t)
	}
}

func updateTemplate(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var t k8s.CustomTemplate
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		t.ID = id
		if !store.Templates.Update(t) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "template not found"})
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

func deleteTemplate(store *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		store.Templates.Delete(id)
		w.WriteHeader(http.StatusNoContent)
	}
}
