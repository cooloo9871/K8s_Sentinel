package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/security"
)

func getSecurityRetention(store *security.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.GetRetention())
	}
}

func setSecurityRetention(store *security.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg security.RetentionConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if cfg.MaxWarnings < 1 || cfg.MaxWarnings > 5000 {
			http.Error(w, "maxWarnings must be 1–5000", http.StatusBadRequest)
			return
		}
		if cfg.MaxCriticals < 1 || cfg.MaxCriticals > 2000 {
			http.Error(w, "maxCriticals must be 1–2000", http.StatusBadRequest)
			return
		}
		if cfg.TTLDays < 1 || cfg.TTLDays > 90 {
			http.Error(w, "ttlDays must be 1–90", http.StatusBadRequest)
			return
		}
		store.SetRetention(cfg)
		writeJSON(w, http.StatusOK, cfg) // echo back validated cfg directly
	}
}

func getAdmissionRetention(store *admission.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.GetRetention())
	}
}

func setAdmissionRetention(store *admission.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg admission.RetentionConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if cfg.MaxEvents < 1 || cfg.MaxEvents > 5000 {
			writeError(w, http.StatusBadRequest, "maxEvents must be 1–5000")
			return
		}
		if cfg.TTLDays < 1 || cfg.TTLDays > 365 {
			writeError(w, http.StatusBadRequest, "ttlDays must be 1–365")
			return
		}
		store.SetRetention(cfg)
		writeJSON(w, http.StatusOK, cfg)
	}
}
