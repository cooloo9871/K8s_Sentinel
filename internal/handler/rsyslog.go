package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/sentinel/internal/rsyslog"
)

func listRsyslog(store *rsyslog.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	}
}

func createRsyslog(store *rsyslog.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg rsyslog.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.Name == "" || cfg.Host == "" {
			http.Error(w, "name and host required", http.StatusBadRequest)
			return
		}
		cfg.ID = fmt.Sprintf("rsyslog-%d", time.Now().UnixMilli())
		if err := store.Create(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, cfg)
	}
}

func updateRsyslog(store *rsyslog.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var cfg rsyslog.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cfg.ID = id
		if !store.Update(cfg) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func deleteRsyslog(store *rsyslog.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if !store.Delete(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func testRsyslog(disp *rsyslog.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg rsyslog.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.Host == "" {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		if cfg.Port == 0 {
			cfg.Port = 514
		}
		if cfg.Protocol == "" {
			cfg.Protocol = "udp"
		}
		if err := disp.TestSend(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
