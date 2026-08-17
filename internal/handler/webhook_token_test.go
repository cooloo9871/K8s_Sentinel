package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cooloo9871/K8s_Sentinel/internal/admission"
)

func postWebhook(h http.Handler, auth string) *httptest.ResponseRecorder {
	return postWebhookPath(h, "/api/admission-events/webhook", auth)
}

func postWebhookPath(h http.Handler, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"items":[]}`))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// With a token configured, the webhook stops being an open write path: anything
// in the cluster could otherwise forge admission events and flood the retention
// cap until the real ones are evicted. The apiserver carries the same token in
// its audit-webhook kubeconfig.
func TestAuditWebhookRequiresTheConfiguredToken(t *testing.T) {
	h := New(Config{Admission: admission.NewStore(""), AuditWebhookToken: "s3cret"})

	if w := postWebhook(h, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}
	if w := postWebhook(h, "Bearer wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", w.Code)
	}
	if w := postWebhook(h, "Bearer s3cret"); w.Code != http.StatusOK {
		t.Errorf("correct token: status = %d, want 200", w.Code)
	}
}

// The token's primary carrier is the webhook URL's last path segment, because
// that is the one place a kubeconfig can reliably deliver a secret to a
// plain-HTTP server — client-go silently refuses to send bearer tokens over
// http, so the kubeconfig's user.token never arrives at all.
func TestAuditWebhookAcceptsTheTokenInThePath(t *testing.T) {
	h := New(Config{Admission: admission.NewStore(""), AuditWebhookToken: "s3cret"})

	if w := postWebhookPath(h, "/api/admission-events/webhook/s3cret", ""); w.Code != http.StatusOK {
		t.Errorf("token in path: status = %d, want 200", w.Code)
	}
	if w := postWebhookPath(h, "/api/admission-events/webhook/wrong", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token in path: status = %d, want 401", w.Code)
	}
	// The apiserver appends ?timeout=30s to whatever the kubeconfig's server
	// URL says, so the token segment has to survive alongside a query string.
	if w := postWebhookPath(h, "/api/admission-events/webhook/s3cret?timeout=30s", ""); w.Code != http.StatusOK {
		t.Errorf("token in path with query: status = %d, want 200", w.Code)
	}
}

// A token is whatever follows the base path — slashes included. A base64
// token carries them, and refusing to lift it turned every delivery into a
// 404 with the secret printed verbatim in the access log on each retry.
func TestAuditWebhookAcceptsATokenContainingSlashes(t *testing.T) {
	h := New(Config{Admission: admission.NewStore(""), AuditWebhookToken: "s3/cr=t"})
	if w := postWebhookPath(h, "/api/admission-events/webhook/s3/cr=t", ""); w.Code != http.StatusOK {
		t.Errorf("slash token: status = %d, want 200", w.Code)
	}
	// And a wrong multi-segment token is refused, not routed into the void.
	if w := postWebhookPath(h, "/api/admission-events/webhook/a/b/c", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong slash token: status = %d, want 401", w.Code)
	}
}

// The lift happens before the access logger, and has to scrub every place the
// logger reads from — RequestURI is the raw string, unaffected by a Path
// rewrite, and is exactly what the logger prints.
func TestTheTokenNeverReachesTheAccessLog(t *testing.T) {
	var seen *http.Request
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r })
	r := httptest.NewRequest(http.MethodPost, "/api/admission-events/webhook/s3/cret?timeout=30s", nil)
	liftWebhookToken(probe).ServeHTTP(httptest.NewRecorder(), r)

	if seen.Header.Get("X-Audit-Webhook-Token") != "s3/cret" {
		t.Errorf("token header = %q, want s3/cret", seen.Header.Get("X-Audit-Webhook-Token"))
	}
	for what, got := range map[string]string{
		"URL.Path":   seen.URL.Path,
		"RequestURI": seen.RequestURI,
	} {
		if strings.Contains(got, "s3") && strings.Contains(got, "cret") {
			t.Errorf("%s still carries the token: %q", what, got)
		}
	}
	if seen.RequestURI != "/api/admission-events/webhook?timeout=30s" {
		t.Errorf("RequestURI = %q — the query has to survive, the token has to go", seen.RequestURI)
	}
}

// Without a token the endpoint keeps its old behavior — apiserver configs
// written before the token existed carry none, and an upgrade must not silently
// cut off their audit stream.
func TestAuditWebhookStaysOpenWhenNoTokenIsSet(t *testing.T) {
	h := New(Config{Admission: admission.NewStore("")})
	if w := postWebhook(h, ""); w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with no token configured", w.Code)
	}
}
