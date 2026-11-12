package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/alert"
	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

var reviewSecret = []byte("0123456789abcdef0123456789abcdef")

func reviewServer(t *testing.T) (http.Handler, *auth.UserStore, *alert.Store) {
	t.Helper()
	dir := t.TempDir()
	users := auth.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.ChangePassword("admin", "a-new-password"); err != nil {
		t.Fatal(err)
	}
	alerts := alert.NewStore(filepath.Join(dir, "alerts.json"))
	return New(Config{Users: users, Secret: reviewSecret, Alerts: alerts}), users, alerts
}

func reviewToken(t *testing.T, users *auth.UserStore, name string) *http.Cookie {
	t.Helper()
	u, ok := users.Get(name)
	if !ok {
		t.Fatalf("no user %s", name)
	}
	tok, err := auth.SignToken(reviewSecret, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "sentinel_token", Value: tok}
}

func reviewDo(h http.Handler, method, path, body string, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if c != nil {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A session outlived the account it was for: a deleted admin could go on
// creating users with the cookie they still held.
func TestADeletedUsersSessionIsRefused(t *testing.T) {
	h, users, _ := reviewServer(t)
	if err := users.Create("gone", "password-1234", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	c := reviewToken(t, users, "gone")
	if w := reviewDo(h, "GET", "/api/auth/me", "", c, nil); w.Code != http.StatusOK {
		t.Fatalf("before delete = %d", w.Code)
	}
	users.Delete("gone")
	if w := reviewDo(h, "GET", "/api/auth/me", "", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("after delete = %d, want 401", w.Code)
	}
}

// Resetting a password did not end the sessions already open on it.
func TestAPasswordChangeEndsEarlierSessions(t *testing.T) {
	h, users, _ := reviewServer(t)
	if err := users.Create("eve", "password-1234", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	u, _ := users.Get("eve")
	old, _ := auth.SignToken(reviewSecret, u, time.Hour)
	time.Sleep(1100 * time.Millisecond) // the comparison is in whole seconds
	if err := users.ChangePassword("eve", "password-5678"); err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: "sentinel_token", Value: old}
	if w := reviewDo(h, "GET", "/api/auth/me", "", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("old session after a password change = %d, want 401", w.Code)
	}
	if w := reviewDo(h, "GET", "/api/auth/me", "", reviewToken(t, users, "eve"), nil); w.Code != http.StatusOK {
		t.Errorf("a new session = %d, want 200", w.Code)
	}
}

// A page on another origin of the same site could post with the admin's cookie.
func TestACrossOriginWriteIsRefused(t *testing.T) {
	h, users, _ := reviewServer(t)
	c := reviewToken(t, users, "admin")
	body := `{"username":"x","password":"password-1234","role":"admin"}`
	for name, hdr := range map[string]map[string]string{
		"same-site":    {"Sec-Fetch-Site": "same-site"},
		"cross-site":   {"Sec-Fetch-Site": "cross-site"},
		"other origin": {"Origin": "http://localhost:9999"},
	} {
		if w := reviewDo(h, "POST", "/api/users", body, c, hdr); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, w.Code)
		}
	}
	if _, ok := users.Get("x"); ok {
		t.Fatal("the cross-origin request created a user")
	}
	if w := reviewDo(h, "POST", "/api/users", body, c, map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != http.StatusCreated {
		t.Errorf("same-origin: %d, want 201", w.Code)
	}
}

// A webhook URL is a credential, and a viewer was handed it.
func TestAViewerIsNotShownWebhookURLs(t *testing.T) {
	h, users, alerts := reviewServer(t)
	if err := users.Create("viewer", "password-1234", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	alerts.Create(alert.AlertRule{ID: "a1", Name: "slack", WebhookURL: "https://hooks.slack.com/services/T000/B000/secret"})
	w := reviewDo(h, "GET", "/api/alerts", "", reviewToken(t, users, "viewer"), nil)
	if strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "hooks.slack.com") {
		t.Errorf("viewer sees %s", w.Body.String())
	}
	w = reviewDo(h, "GET", "/api/alerts", "", reviewToken(t, users, "admin"), nil)
	if !strings.Contains(w.Body.String(), "secret") {
		t.Errorf("admin no longer sees the URL: %s", w.Body.String())
	}
}
