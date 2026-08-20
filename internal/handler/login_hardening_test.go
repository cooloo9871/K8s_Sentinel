package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

// withClaims puts an auth.Claims on the request context the way authMiddleware
// would, so handlers and the gate can be exercised in isolation.
func withClaims(r *http.Request, username string, role auth.Role) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), claimsKey,
		&auth.Claims{Username: username, Role: role}))
}

// A user still flagged to change their password may reach only /me and their
// own password change; everything else is 403 until they do.
func TestMustChangeGateBlocksEverythingButThePasswordChange(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json")) // admin flagged
	gate := mustChangeGate(users)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/auth/me", http.StatusOK},
		{http.MethodPut, "/api/users/admin/password", http.StatusOK},
		{http.MethodGet, "/api/cnp", http.StatusForbidden},
		{http.MethodPut, "/api/users/someone-else/password", http.StatusForbidden},
	}
	for _, c := range cases {
		req := withClaims(httptest.NewRequest(c.method, c.path, nil), "admin", auth.RoleAdmin)
		w := httptest.NewRecorder()
		gate(ok).ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, w.Code, c.want)
		}
	}
}

// Once the password is changed the flag clears, so the gate lets everything
// through.
func TestMustChangeGateOpensAfterTheChange(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.ChangePassword("admin", "a-real-password"); err != nil {
		t.Fatal(err)
	}
	req := withClaims(httptest.NewRequest(http.MethodGet, "/api/cnp", nil), "admin", auth.RoleAdmin)
	w := httptest.NewRecorder()
	reached := false
	mustChangeGate(users)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	})).ServeHTTP(w, req)
	if !reached {
		t.Error("gate blocked a user who no longer needs to change their password")
	}
}

// changePwd drives changePasswordHandler with the caller identity and target in
// place, the way the router would.
func changePwd(users *auth.UserStore, caller string, role auth.Role, target, body string) *httptest.ResponseRecorder {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("username", target)
	r := httptest.NewRequest(http.MethodPut, "/api/users/"+target+"/password", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
	r = withClaims(r, caller, role)
	w := httptest.NewRecorder()
	changePasswordHandler(users)(w, r)
	return w
}

// Changing your own password must prove the current one; a wrong or missing
// current password is refused.
func TestChangeOwnPasswordRequiresTheCurrentOne(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	// admin/admin is the bootstrap credential.

	if w := changePwd(users, "admin", auth.RoleAdmin, "admin",
		`{"currentPassword":"wrong","password":"a-new-password"}`); w.Code != http.StatusForbidden {
		t.Errorf("wrong current password: status = %d, want 403", w.Code)
	}
	if _, ok := users.Authenticate("admin", "admin"); !ok {
		t.Error("the password was changed despite a wrong current password")
	}
	if w := changePwd(users, "admin", auth.RoleAdmin, "admin",
		`{"currentPassword":"admin","password":"a-new-password"}`); w.Code != http.StatusNoContent {
		t.Errorf("correct current password: status = %d, want 204", w.Code)
	}
	if _, ok := users.Authenticate("admin", "a-new-password"); !ok {
		t.Error("the password was not changed despite the correct current password")
	}
}

// An admin resetting someone else's password does not supply their old one.
func TestAdminResetsAnotherUserWithoutTheirCurrentPassword(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Create("bob", "bobs-password", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if w := changePwd(users, "admin", auth.RoleAdmin, "bob",
		`{"password":"reset-by-admin"}`); w.Code != http.StatusNoContent {
		t.Errorf("admin reset: status = %d, want 204", w.Code)
	}
	if _, ok := users.Authenticate("bob", "reset-by-admin"); !ok {
		t.Error("admin reset did not take effect")
	}
}

// The minimum length is enforced at the handler too, not only the store.
func TestChangePasswordRejectsTooShort(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	w := changePwd(users, "admin", auth.RoleAdmin, "admin",
		`{"currentPassword":"admin","password":"short"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("too-short password: status = %d, want 400", w.Code)
	}
}

// A password change is audited whether it succeeds or fails — it lives outside
// the admin group, so it carries its own audit middleware, and a rejected
// attempt (wrong current password) is exactly what the log should keep.
func TestChangePasswordIsAuditedOnSuccessAndFailure(t *testing.T) {
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json")) // admin/admin
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.json"))

	r := chi.NewRouter()
	// Inject the caller the way authMiddleware would, then audit, then handle —
	// the same order as the real route.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, withClaims(req, "admin", auth.RoleAdmin))
		})
	})
	r.With(auditMiddleware(store)).
		Put("/api/users/{username}/password", changePasswordHandler(users))

	serve := func(body string) {
		req := httptest.NewRequest(http.MethodPut, "/api/users/admin/password", strings.NewReader(body))
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	serve(`{"currentPassword":"wrong","password":"a-new-password"}`) // 403
	serve(`{"currentPassword":"admin","password":"a-new-password"}`) // 204

	got := store.List() // newest first
	if len(got) != 2 {
		t.Fatalf("recorded %d entries, want 2", len(got))
	}
	if got[0].Status != http.StatusNoContent || got[1].Status != http.StatusForbidden {
		t.Errorf("statuses = %d then %d, want 204 then 403", got[0].Status, got[1].Status)
	}
	for _, e := range got {
		if e.Action != "Change user password" || e.Target != "admin" {
			t.Errorf("entry = %q/%q, want %q/%q", e.Action, e.Target, "Change user password", "admin")
		}
	}
}
