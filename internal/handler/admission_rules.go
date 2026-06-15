package handler

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/sentinel/internal/admission"
)

func listAdmissionRules(store *admission.RuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	}
}

func createAdmissionRule(store *admission.RuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "body required", http.StatusBadRequest)
			return
		}
		rule, err := store.Create(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	}
}

func updateAdmissionRule(store *admission.RuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "body required", http.StatusBadRequest)
			return
		}
		rule, err := store.Update(id, string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func toggleAdmissionRule(store *admission.RuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		enabled := r.URL.Query().Get("enabled") == "true"
		if !store.SetEnabled(id, enabled) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteAdmissionRule(store *admission.RuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if !store.Delete(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
