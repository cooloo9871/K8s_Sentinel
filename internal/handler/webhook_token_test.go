package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cooloo9871/K8s_Sentinel/internal/admission"
)

func postWebhook(h http.Handler, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/admission-events/webhook",
		strings.NewReader(`{"items":[]}`))
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

// Without a token the endpoint keeps its old behavior — apiserver configs
// written before the token existed carry none, and an upgrade must not silently
// cut off their audit stream.
func TestAuditWebhookStaysOpenWhenNoTokenIsSet(t *testing.T) {
	h := New(Config{Admission: admission.NewStore("")})
	if w := postWebhook(h, ""); w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with no token configured", w.Code)
	}
}
