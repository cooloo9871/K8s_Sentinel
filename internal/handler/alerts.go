package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/sentinel/internal/alert"
)

func listAlerts(store *alert.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	}
}

func createAlert(store *alert.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule alert.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if rule.Name == "" || rule.WebhookURL == "" {
			http.Error(w, "name and webhookURL required", http.StatusBadRequest)
			return
		}
		rule.ID = fmt.Sprintf("alert-%d", time.Now().UnixMilli())
		if err := store.Create(rule); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	}
}

func updateAlert(store *alert.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var rule alert.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rule.ID = id
		if !store.Update(rule) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func deleteAlert(store *alert.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if !store.Delete(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func testAlert(disp *alert.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			WebhookURL string `json:"webhookURL"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.WebhookURL == "" {
			http.Error(w, "webhookURL required", http.StatusBadRequest)
			return
		}
		if err := disp.SendTest(body.WebhookURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
