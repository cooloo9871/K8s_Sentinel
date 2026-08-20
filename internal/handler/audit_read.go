package handler

import (
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
)

// listAudit returns the admin action log, newest first. Admin-only, and a GET,
// so the audit middleware does not record the reading of it.
func listAudit(store *audit.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusOK, []audit.Entry{})
			return
		}
		writeJSON(w, http.StatusOK, store.List())
	}
}
