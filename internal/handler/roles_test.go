package handler

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

// rolesServer is a handler tree with a full admin "root" and the stores behind it.
func rolesServer(t *testing.T) (http.Handler, *auth.UserStore, *auth.RoleStore, func(string) *http.Cookie) {
	t.Helper()
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	roles := auth.NewRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	secret := []byte("0123456789abcdef0123456789abcdef")
	users.Delete("admin")
	if err := users.Create("root", "longenough", auth.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	cookie := func(name string) *http.Cookie {
		u, ok := users.Get(name)
		if !ok {
			t.Fatalf("no account %s", name)
		}
		token, err := auth.SignToken(secret, u, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: "sentinel_token", Value: token}
	}
	return New(Config{Users: users, Roles: roles, Secret: secret}), users, roles, cookie
}

func TestRolesAreMadeChangedAndDeleted(t *testing.T) {
	h, users, _, cookie := rolesServer(t)
	root := cookie("root")

	if w := do(h, root, http.MethodPost, "/api/roles", `{"name":"netops","permissions":{"network":"manage","events":"view"}}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, root, http.MethodPost, "/api/roles", `{"name":"NetOps","permissions":{}}`); w.Code != http.StatusConflict {
		t.Errorf("a taken name: %d", w.Code)
	}
	if w := do(h, root, http.MethodPost, "/api/roles", `{"name":"x","permissions":{"network":"owner"}}`); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown level: %d", w.Code)
	}
	for _, builtIn := range []string{"admin", "viewer"} {
		if w := do(h, root, http.MethodPut, "/api/roles/"+builtIn, `{"permissions":{}}`); w.Code != http.StatusConflict {
			t.Errorf("edit %s: %d", builtIn, w.Code)
		}
		if w := do(h, root, http.MethodDelete, "/api/roles/"+builtIn, ""); w.Code != http.StatusConflict {
			t.Errorf("delete %s: %d", builtIn, w.Code)
		}
	}

	// An account is made with it, and only with a role that exists.
	if w := do(h, root, http.MethodPost, "/api/users", `{"username":"nina","password":"longenough","role":"netops"}`); w.Code != http.StatusCreated {
		t.Fatalf("create account: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, root, http.MethodPost, "/api/users", `{"username":"zed","password":"longenough","role":"nobody"}`); w.Code != http.StatusBadRequest {
		t.Errorf("an account with a role that is not there: %d", w.Code)
	}
	if w := do(h, root, http.MethodGet, "/api/roles", ""); !strings.Contains(w.Body.String(), `"name":"netops"`) || !strings.Contains(w.Body.String(), `"users":1`) {
		t.Errorf("list = %s", w.Body.String())
	}

	// The role grants what it says and no more.
	nina := cookie("nina")
	if w := do(h, nina, http.MethodGet, "/api/auth/me", ""); !strings.Contains(w.Body.String(), `"network":"manage"`) || !strings.Contains(w.Body.String(), `"system":"none"`) {
		t.Errorf("me = %s", w.Body.String())
	}
	if w := do(h, nina, http.MethodGet, "/api/users", ""); w.Code != http.StatusForbidden {
		t.Errorf("accounts: %d", w.Code)
	}
	if w := do(h, nina, http.MethodPost, "/api/roles", `{"name":"mine","permissions":{"system":"manage"}}`); w.Code != http.StatusForbidden {
		t.Errorf("making a role: %d", w.Code)
	}

	// A change applies to a session already open.
	if w := do(h, root, http.MethodPut, "/api/roles/netops", `{"permissions":{"system":"view"}}`); w.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, nina, http.MethodGet, "/api/users", ""); w.Code != http.StatusOK {
		t.Errorf("accounts after the role was given them: %d", w.Code)
	}

	// A role an account has stays, and the refusal says how many have it.
	if w := do(h, root, http.MethodDelete, "/api/roles/netops", ""); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "1 account has this role") {
		t.Errorf("delete in use: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, root, http.MethodPut, "/api/users/nina/role", `{"role":"viewer"}`); w.Code != http.StatusNoContent {
		t.Fatalf("set role: %d %s", w.Code, w.Body.String())
	}
	if u, _ := users.Get("nina"); u.Role != auth.RoleViewer {
		t.Errorf("role = %q", u.Role)
	}
	if w := do(h, root, http.MethodDelete, "/api/roles/netops", ""); w.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, root, http.MethodPut, "/api/users/nina/role", `{"role":"netops"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a role that is gone: %d", w.Code)
	}
}

// An account whose role is gone can do nothing but be itself.
func TestAnAccountOnARoleThatIsGoneHasNoPermissions(t *testing.T) {
	h, users, _, cookie := rolesServer(t)
	if err := users.Create("orphan", "longenough", "vanished", nil); err != nil {
		t.Fatal(err)
	}
	c := cookie("orphan")
	if w := do(h, c, http.MethodGet, "/api/auth/me", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"events":"none"`) {
		t.Errorf("me: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, c, http.MethodGet, "/api/security-events", ""); w.Code != http.StatusForbidden {
		t.Errorf("events: %d", w.Code)
	}
	if w := do(h, c, http.MethodPut, "/api/users/orphan/password", `{"password":"another-one","currentPassword":"longenough"}`); w.Code != http.StatusNoContent {
		t.Errorf("own password: %d %s", w.Code, w.Body.String())
	}
}

// There is always an account with the admin role and the whole cluster, also
// when the one asking holds a role of its own making.
func TestTheLastFullAdminStays(t *testing.T) {
	h, users, roles, cookie := rolesServer(t)
	if err := roles.Create(auth.RoleDef{Name: "sysadmin", Permissions: auth.Permissions{auth.AreaSystem: auth.LevelManage}}); err != nil {
		t.Fatal(err)
	}
	if err := users.Create("sam", "longenough", "sysadmin", nil); err != nil {
		t.Fatal(err)
	}
	sam := cookie("sam")
	if w := do(h, sam, http.MethodDelete, "/api/users/root", ""); w.Code != http.StatusConflict {
		t.Errorf("delete: %d", w.Code)
	}
	if w := do(h, sam, http.MethodPut, "/api/users/root/role", `{"role":"viewer"}`); w.Code != http.StatusConflict {
		t.Errorf("another role: %d", w.Code)
	}
	if w := do(h, sam, http.MethodPut, "/api/users/root/namespaces", `{"namespaces":["team-a"]}`); w.Code != http.StatusConflict {
		t.Errorf("a limit: %d", w.Code)
	}
	if u, ok := users.Get("root"); !ok || u.Role != auth.RoleAdmin || len(u.Namespaces) != 0 {
		t.Errorf("root = %+v, %v", u, ok)
	}
	// Nobody changes their own role.
	if w := do(h, sam, http.MethodPut, "/api/users/sam/role", `{"role":"admin"}`); w.Code != http.StatusBadRequest {
		t.Errorf("own role: %d", w.Code)
	}
	// With a second full admin, the first is an account like any other.
	if w := do(h, sam, http.MethodPost, "/api/users", `{"username":"root2","password":"longenough","role":"admin"}`); w.Code != http.StatusCreated {
		t.Fatalf("second admin: %d", w.Code)
	}
	if w := do(h, sam, http.MethodPut, "/api/users/root/role", `{"role":"viewer"}`); w.Code != http.StatusNoContent {
		t.Errorf("another role with a second admin there: %d", w.Code)
	}
}

// An account limited to namespaces manages no roles and no accounts, whatever
// its role says.
func TestALimitedAccountManagesNoRoles(t *testing.T) {
	h, _, c := scopedSession(t, auth.RoleAdmin)
	if w := do(h, c, http.MethodGet, "/api/roles", ""); w.Code != http.StatusForbidden {
		t.Errorf("list: %d", w.Code)
	}
	if w := do(h, c, http.MethodPost, "/api/roles", `{"name":"mine","permissions":{}}`); w.Code != http.StatusForbidden {
		t.Errorf("create: %d", w.Code)
	}
	if w := do(h, c, http.MethodPut, "/api/users/admin/role", `{"role":"viewer"}`); w.Code != http.StatusForbidden {
		t.Errorf("set role: %d", w.Code)
	}
}
