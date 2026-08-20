package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
)

// serveThroughAudit runs one request through the audit middleware mounted on a
// chi route, so the recorded action and target come from the real route
// pattern and params rather than a hand-built context.
func serveThroughAudit(store *audit.Store, method, pattern, path, body string) {
	r := chi.NewRouter()
	r.Use(auditMiddleware(store))
	r.MethodFunc(method, pattern, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	r.ServeHTTP(httptest.NewRecorder(), req)
}

func TestAuditRecordsAdminWrites(t *testing.T) {
	store := audit.NewStore(t.TempDir() + "/audit.json")

	// A URL-param target (delete).
	serveThroughAudit(store, http.MethodDelete, "/api/cnp/{name}", "/api/cnp/deny-egress", "")
	// A namespace/pod target from the URL (release).
	serveThroughAudit(store, http.MethodDelete, "/api/quarantine/{namespace}/{pod}", "/api/quarantine/demo/web-1", "")
	// A body target (quarantine names its subject in the body).
	serveThroughAudit(store, http.MethodPost, "/api/quarantine", "/api/quarantine", `{"namespace":"demo","pod":"api-2"}`)
	// A raw-YAML apply names itself in the manifest.
	serveThroughAudit(store, http.MethodPost, "/api/cnp", "/api/cnp",
		"{\"rawYaml\":\"kind: CiliumNetworkPolicy\\nmetadata:\\n  name: allow-dns\\n\"}")

	got := store.List() // newest first
	if len(got) != 4 {
		t.Fatalf("recorded %d entries, want 4", len(got))
	}
	want := []struct{ action, target string }{
		{"Create network policy", "allow-dns"},
		{"Quarantine pod", "demo/api-2"},
		{"Release pod", "demo/web-1"},
		{"Delete network policy", "deny-egress"},
	}
	for i, w := range want {
		if got[i].Action != w.action || got[i].Target != w.target {
			t.Errorf("entry %d = %q/%q, want %q/%q", i, got[i].Action, got[i].Target, w.action, w.target)
		}
		if got[i].Status != http.StatusNoContent {
			t.Errorf("entry %d status = %d, want 204", i, got[i].Status)
		}
	}
}

// GET must not be recorded: the log is of changes, not reads. Reading the audit
// log itself must not append to it.
func TestAuditIgnoresReads(t *testing.T) {
	store := audit.NewStore(t.TempDir() + "/audit.json")
	serveThroughAudit(store, http.MethodGet, "/api/audit", "/api/audit", "")
	if n := len(store.List()); n != 0 {
		t.Errorf("recorded %d entries for a GET, want 0", n)
	}
}
