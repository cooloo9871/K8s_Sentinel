package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cooloo9871/sentinel/internal/auth"
)

// Logging out is supposed to put the token on the blocklist so a copy of the
// cookie cannot be replayed. The handler read its claims from the request
// context, but the route is registered outside the auth middleware — so there
// were never any claims there, nothing was ever revoked, and the whole blocklist
// was dead code.
func TestLoggingOutRevokesTheToken(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	secret := []byte("0123456789abcdef0123456789abcdef")

	u, ok := users.Authenticate("admin", "admin")
	if !ok {
		t.Fatal("bootstrap admin cannot log in")
	}
	token, err := auth.SignToken(secret, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseToken(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if users.IsTokenRevoked(claims.ID) {
		t.Fatal("a fresh token is already revoked")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_token", Value: token})
	w := httptest.NewRecorder()
	logoutHandler(users, secret)(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !users.IsTokenRevoked(claims.ID) {
		t.Error("the token was not revoked, so the cookie still works after logout")
	}
}

// Logging out has to clear the cookie even when the token cannot be parsed,
// which is the reason the route is public in the first place.
func TestLoggingOutWithAnUnusableTokenStillClearsTheCookie(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_token", Value: "not-a-jwt"})
	w := httptest.NewRecorder()

	logoutHandler(users, []byte("0123456789abcdef0123456789abcdef"))(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "sentinel_token" && c.MaxAge >= 0 {
			t.Errorf("cookie MaxAge = %d, want it expired", c.MaxAge)
		}
	}
}

// A token signed with a different secret must not be accepted for revocation
// either — it is not ours to revoke, and honouring it would let anyone fill the
// blocklist.
func TestLoggingOutIgnoresAForeignToken(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	u, _ := users.Authenticate("admin", "admin")
	foreign, err := auth.SignToken([]byte("ffffffffffffffffffffffffffffffff"), u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := auth.ParseToken([]byte("ffffffffffffffffffffffffffffffff"), foreign)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_token", Value: foreign})
	logoutHandler(users, []byte("0123456789abcdef0123456789abcdef"))(httptest.NewRecorder(), req)

	if users.IsTokenRevoked(claims.ID) {
		t.Error("a token signed with another secret was added to the blocklist")
	}
}
