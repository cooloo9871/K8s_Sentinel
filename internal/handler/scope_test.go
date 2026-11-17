package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

// scopedSession returns the handler tree and a session cookie for an account
// limited to the namespace "team-a".
func scopedSession(t *testing.T, role auth.Role) (http.Handler, *auth.UserStore, *http.Cookie) {
	t.Helper()
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := users.Create("alice", "longenough", role, []string{"team-a"}); err != nil {
		t.Fatal(err)
	}
	u, _ := users.Get("alice")
	token, err := auth.SignToken(secret, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Users: users, Secret: secret}), users, &http.Cookie{Name: "sentinel_token", Value: token}
}

func do(h http.Handler, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// What belongs to the cluster is refused to an account limited to namespaces,
// whatever its role, before the handler is reached.
func TestClusterRoutesRefuseALimitedAccount(t *testing.T) {
	h, _, c := scopedSession(t, auth.RoleAdmin)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/mode"},
		{http.MethodPut, "/api/mode"},
		{http.MethodGet, "/api/tetragon/agents"},
		{http.MethodGet, "/api/ingestion/health"},
		{http.MethodGet, "/api/settings/session-ttl"},
		{http.MethodPut, "/api/settings/session-ttl"},
		{http.MethodGet, "/api/alerts"},
		{http.MethodPost, "/api/alerts"},
		{http.MethodGet, "/api/rsyslog"},
		{http.MethodPost, "/api/rsyslog"},
		{http.MethodPut, "/api/security-events/retention"},
		{http.MethodPut, "/api/admission-events/retention"},
		{http.MethodGet, "/api/vap"},
		{http.MethodGet, "/api/vap/x"},
		{http.MethodPost, "/api/vap"},
		{http.MethodDelete, "/api/vap/x"},
		{http.MethodGet, "/api/vap-bindings"},
		{http.MethodPost, "/api/vap-bindings"},
		{http.MethodGet, "/api/registries"},
		{http.MethodPost, "/api/registries"},
		{http.MethodGet, "/api/registries/x/findings"},
		{http.MethodGet, "/api/audit"},
		{http.MethodGet, "/api/users"},
		{http.MethodPost, "/api/users"},
		{http.MethodDelete, "/api/users/admin"},
		{http.MethodPut, "/api/users/alice/namespaces"},
		{http.MethodPost, "/api/templates"},
		{http.MethodDelete, "/api/templates/x"},
	} {
		if w := do(h, c, r.method, r.path, "{}"); w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", r.method, r.path, w.Code)
		}
	}
}

// In what is namespaced, another namespace and the cluster-wide kind are
// refused before anything is read or written.
func TestNamespacedRoutesRefuseOtherNamespaces(t *testing.T) {
	h, _, c := scopedSession(t, auth.RoleAdmin)
	clusterPolicy := `{"source":"yaml","rawYaml":"kind: TracingPolicy\nmetadata:\n  name: x\n"}`
	otherPolicy := `{"source":"yaml","rawYaml":"kind: TracingPolicyNamespaced\nmetadata:\n  name: x\n  namespace: team-b\n"}`
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/policies/x", ""},
		{http.MethodGet, "/api/policies/x?namespace=team-b", ""},
		{http.MethodPost, "/api/policies", clusterPolicy},
		{http.MethodPost, "/api/policies", otherPolicy},
		{http.MethodPost, "/api/policies", `{"source":"form","form":{"name":"x"}}`},
		{http.MethodPost, "/api/policies", `{"source":"form","form":{"name":"x","namespace":"team-b"}}`},
		// Said to be in team-a, written to team-b.
		{http.MethodPut, "/api/policies/x?namespace=team-a", otherPolicy},
		{http.MethodPut, "/api/policies/x?namespace=team-a", clusterPolicy},
		{http.MethodPut, "/api/policies/x", otherPolicy},
		{http.MethodDelete, "/api/policies/x", ""},
		{http.MethodDelete, "/api/policies/x?namespace=team-b", ""},
		{http.MethodPut, "/api/policies/x/mode?namespace=team-b", `{"mode":"Protect"}`},
		{http.MethodPut, "/api/policies/x/mode", `{"mode":"Protect"}`},
		{http.MethodGet, "/api/cnp/x?scope=cluster", ""},
		{http.MethodGet, "/api/cnp/x?scope=cluster&namespace=team-a", ""},
		{http.MethodGet, "/api/cnp/x?namespace=team-b", ""},
		{http.MethodPost, "/api/cnp", `{"rawYaml":"kind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: x\n"}`},
		{http.MethodPost, "/api/cnp", `{"rawYaml":"kind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: x\n  namespace: team-a\n"}`},
		{http.MethodPost, "/api/cnp", `{"rawYaml":"kind: CiliumNetworkPolicy\nmetadata:\n  name: x\n  namespace: team-b\n"}`},
		{http.MethodPost, "/api/cnp", `{"rawYaml":"kind: CiliumNetworkPolicy\nmetadata:\n  name: x\n"}`},
		{http.MethodPost, "/api/cnp", `{"rawYaml":"\tnot yaml"}`},
		{http.MethodDelete, "/api/cnp/x?scope=cluster", ""},
		{http.MethodDelete, "/api/cnp/x?namespace=team-b", ""},
		{http.MethodGet, "/api/pods/team-b/p/labels", ""},
		{http.MethodPost, "/api/selector-preview", `{"namespace":"team-b"}`},
		{http.MethodPost, "/api/selector-preview", `{}`},
		{http.MethodGet, "/api/vulnerabilities/team-b/Deployment/x", ""},
		{http.MethodPost, "/api/quarantine", `{"namespace":"team-b","pod":"p"}`},
		{http.MethodDelete, "/api/quarantine/team-b/p", ""},
	} {
		if w := do(h, c, r.method, r.path, r.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s %s = %d, want 403", r.method, r.path, r.body, w.Code)
		}
	}
}

// An admin of some namespaces is not an admin of the accounts: resetting
// another account's password would hand it the whole cluster.
func TestALimitedAdminCannotSetAnotherPassword(t *testing.T) {
	h, users, c := scopedSession(t, auth.RoleAdmin)
	if w := do(h, c, http.MethodPut, "/api/users/admin/password", `{"password":"takenover1"}`); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if _, ok := users.Authenticate("admin", "takenover1"); ok {
		t.Error("the admin password was changed")
	}
	// Its own it may change, as anyone may.
	if w := do(h, c, http.MethodPut, "/api/users/alice/password", `{"password":"newpassword","currentPassword":"longenough"}`); w.Code != http.StatusNoContent {
		t.Errorf("own password: status = %d, want 204", w.Code)
	}
}

// The limit is the account's as it is now, not as it was at sign-in.
func TestALimitTakesEffectOnASessionAlreadyOpen(t *testing.T) {
	h, users, c := scopedSession(t, auth.RoleViewer)
	if w := do(h, c, http.MethodGet, "/api/auth/me", ""); !strings.Contains(w.Body.String(), `"namespaces":["team-a"]`) {
		t.Errorf("me = %s", w.Body.String())
	}
	users.SetNamespaces("alice", nil)
	if w := do(h, c, http.MethodGet, "/api/settings/session-ttl", ""); w.Code != http.StatusOK {
		t.Errorf("with the limit lifted: status = %d, want 200", w.Code)
	}
	users.SetNamespaces("alice", []string{"team-b"})
	if w := do(h, c, http.MethodGet, "/api/settings/session-ttl", ""); w.Code != http.StatusForbidden {
		t.Errorf("with a limit set: status = %d, want 403", w.Code)
	}
}

func TestScope(t *testing.T) {
	limited := scope{"team-a", "team-b"}
	for ns, want := range map[string]bool{"team-a": true, "team-b": true, "team-c": false, "": false, "team": false} {
		if got := limited.allows(ns); got != want {
			t.Errorf("limited.allows(%q) = %v, want %v", ns, got, want)
		}
	}
	if whole := (scope{}); !whole.allows("") || !whole.allows("anything") {
		t.Error("an account with no limit must reach everything")
	}
	got := inScope(limited, []string{"team-a", "kube-system", "", "team-b"}, func(s string) string { return s })
	if len(got) != 2 || got[0] != "team-a" || got[1] != "team-b" {
		t.Errorf("inScope = %v", got)
	}
}

func TestCleanNamespaces(t *testing.T) {
	got, err := cleanNamespaces([]string{" team-b ", "team-a", "", "team-b"})
	if err != nil || len(got) != 2 || got[0] != "team-a" || got[1] != "team-b" {
		t.Errorf("cleanNamespaces = %v, %v", got, err)
	}
	for _, bad := range []string{"Team", "a b", "*", "a/b"} {
		if _, err := cleanNamespaces([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a namespace", bad)
		}
	}
}
