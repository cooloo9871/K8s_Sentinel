package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
)

// auditMiddleware records every state-changing admin request. It sits on the
// admin group so a new write route is covered without a per-handler call to
// remember. Reads (GET) are skipped: the log is of what changed, not what was
// looked at.
func auditMiddleware(store *audit.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Buffer the body so the target can be read from it (a create names
			// its subject in the body, not the URL) and the handler still gets
			// it. Capped, since this runs before the handler's own limit.
			var body []byte
			if r.Body != nil {
				body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			store.Record(audit.Entry{
				User:   usernameFromCtx(r),
				Action: describeAction(r),
				Target: auditTarget(r, body),
				Method: r.Method,
				Path:   r.URL.Path,
				Status: rec.status,
			})
		})
	}
}

// statusRecorder captures the response status the audit entry records.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true // a body without an explicit WriteHeader is a 200
	return s.ResponseWriter.Write(b)
}

// describeAction turns the request into a human-readable action, keyed on the
// chi route pattern so the label is stable regardless of the concrete name.
func describeAction(r *http.Request) string {
	pattern := ""
	if rc := chi.RouteContext(r.Context()); rc != nil {
		pattern = rc.RoutePattern()
	}
	if a, ok := actionLabels[r.Method+" "+pattern]; ok {
		return a
	}
	// A route without a curated label still records something legible rather
	// than nothing, so a new write route is never silently unlabelled.
	return r.Method + " " + pattern
}

var actionLabels = map[string]string{
	"POST /api/policies":                       "Create tracing policy",
	"PUT /api/policies/{name}":                 "Update tracing policy",
	"PUT /api/policies/{name}/mode":            "Set tracing policy mode",
	"DELETE /api/policies/{name}":              "Delete tracing policy",
	"PUT /api/mode":                            "Set global protect mode",
	"POST /api/cnp":                            "Create network policy",
	"PUT /api/cnp/{name}":                      "Update network policy",
	"DELETE /api/cnp/{name}":                   "Delete network policy",
	"POST /api/vap":                            "Create admission policy",
	"PUT /api/vap/{name}":                      "Update admission policy",
	"DELETE /api/vap/{name}":                   "Delete admission policy",
	"POST /api/vap-bindings":                   "Create admission binding",
	"PUT /api/vap-bindings/{name}":             "Update admission binding",
	"DELETE /api/vap-bindings/{name}":          "Delete admission binding",
	"POST /api/quarantine":                     "Quarantine pod",
	"DELETE /api/quarantine/{namespace}/{pod}": "Release pod",
	"POST /api/users":                          "Create user",
	"DELETE /api/users/{username}":             "Delete user",
	"PUT /api/users/{username}/password":       "Change user password",
	"PUT /api/settings/session-ttl":            "Set session timeout",
	"POST /api/alerts":                         "Create alert rule",
	"PUT /api/alerts/{id}":                     "Update alert rule",
	"DELETE /api/alerts/{id}":                  "Delete alert rule",
	"POST /api/alerts/test":                    "Send test alert",
	"POST /api/rsyslog":                        "Create syslog config",
	"PUT /api/rsyslog/{id}":                    "Update syslog config",
	"DELETE /api/rsyslog/{id}":                 "Delete syslog config",
	"POST /api/rsyslog/test":                   "Send test syslog",
	"POST /api/templates":                      "Create policy template",
	"PUT /api/templates/{id}":                  "Update policy template",
	"DELETE /api/templates/{id}":               "Delete policy template",
	"DELETE /api/discovery/profiles":           "Clear behavior discovery",
	"PUT /api/security-events/retention":       "Set security event retention",
	"PUT /api/admission-events/retention":      "Set admission event retention",
}

// auditTarget names what was acted on: the URL params when the route carries
// them (update/delete/mode/release), else the identifying fields of the body
// (a create names its subject there).
func auditTarget(r *http.Request, body []byte) string {
	rc := chi.RouteContext(r.Context())
	if rc != nil {
		if ns, pod := chi.URLParamFromCtx(r.Context(), "namespace"), chi.URLParamFromCtx(r.Context(), "pod"); ns != "" && pod != "" {
			return ns + "/" + pod
		}
		for _, k := range []string{"name", "username", "id"} {
			if v := chi.URLParamFromCtx(r.Context(), k); v != "" {
				return v
			}
		}
	}
	// Body targets, best-effort: the common identifying fields across the
	// create routes. Parse failures leave the target empty rather than erroring.
	if len(body) > 0 {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if ns, pod := str(m["namespace"]), str(m["pod"]); ns != "" && pod != "" {
				return ns + "/" + pod
			}
			for _, k := range []string{"name", "username"} {
				if v := str(m[k]); v != "" {
					return v
				}
			}
			// A raw-YAML apply carries the object; name it if the manifest names itself.
			if raw := str(m["rawYaml"]); raw != "" {
				if n := yamlName(raw); n != "" {
					return n
				}
			}
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// yamlName pulls metadata.name out of a manifest without a full YAML parse:
// the first "name:" under a "metadata:" block, which is all the audit target
// needs.
func yamlName(raw string) string {
	inMeta := false
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		indented := line != trimmed && trimmed != ""
		if trimmed == "metadata:" {
			inMeta = true
			continue
		}
		if inMeta && !indented {
			return "" // left the metadata block without finding a name
		}
		if inMeta && strings.HasPrefix(trimmed, "name:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "name:")), `"'`)
		}
	}
	return ""
}
