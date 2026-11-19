package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

// builtInPerms is what a built-in role grants, for a test that puts claims on a
// request by hand.
func builtInPerms(role auth.Role) auth.Permissions {
	def, _ := auth.NewRoleStore("").Get(role)
	return def.Permissions
}

const roleRefusal = "this account's role does not allow this"

// What every route behind the session asks of the account's role. A route that
// is added and not put here fails TestEveryRouteDeclaresAPermission: a page
// hidden in the interface is not what keeps its data from an account.
var (
	tracingV = []perm{{auth.AreaTracing, auth.LevelView}}
	tracingM = []perm{{auth.AreaTracing, auth.LevelManage}}
	networkV = []perm{{auth.AreaNetwork, auth.LevelView}}
	networkM = []perm{{auth.AreaNetwork, auth.LevelManage}}
	admitV   = []perm{{auth.AreaAdmission, auth.LevelView}}
	admitM   = []perm{{auth.AreaAdmission, auth.LevelManage}}
	quarV    = []perm{{auth.AreaQuarantine, auth.LevelView}}
	quarM    = []perm{{auth.AreaQuarantine, auth.LevelManage}}
	eventsV  = []perm{{auth.AreaEvents, auth.LevelView}}
	vulnV    = []perm{{auth.AreaVulnerabilities, auth.LevelView}}
	vulnM    = []perm{{auth.AreaVulnerabilities, auth.LevelManage}}
	notifyV  = []perm{{auth.AreaNotifications, auth.LevelView}}
	notifyM  = []perm{{auth.AreaNotifications, auth.LevelManage}}
	systemV  = []perm{{auth.AreaSystem, auth.LevelView}}
	systemM  = []perm{{auth.AreaSystem, auth.LevelManage}}
	// Read by the event pages and by the settings page.
	retentionV = []perm{{auth.AreaEvents, auth.LevelView}, {auth.AreaSystem, auth.LevelView}}
)

// Open to every signed-in account, whatever its role.
var openRoutes = map[string]bool{
	"GET /api/auth/me":                       true,
	"PUT /api/users/{username}/password":     true,
	"GET /api/namespaces":                    true,
	"GET /api/pods/{namespace}/{pod}/labels": true,
	"POST /api/selector-preview":             true,
	"GET /api/cluster/cidr":                  true,
}

// Not behind the session at all.
var publicRoutes = map[string]bool{
	"POST /api/auth/login":  true,
	"POST /api/auth/logout": true,
}

var routePerms = map[string][]perm{
	"GET /api/policies":              tracingV,
	"POST /api/policies/preview":     tracingV,
	"GET /api/policies/{name}":       tracingV,
	"GET /api/discovery/profiles":    tracingV,
	"GET /api/templates":             tracingV,
	"GET /api/mode":                  tracingV,
	"POST /api/policies":             tracingM,
	"PUT /api/policies/{name}":       tracingM,
	"PUT /api/policies/{name}/mode":  tracingM,
	"DELETE /api/policies/{name}":    tracingM,
	"DELETE /api/discovery/profiles": tracingM,
	"PUT /api/mode":                  tracingM,
	"POST /api/templates":            tracingM,
	"PUT /api/templates/{id}":        tracingM,
	"DELETE /api/templates/{id}":     tracingM,

	"GET /api/network-topology":    networkV,
	"GET /api/cilium/status":       networkV,
	"GET /api/cilium/flows/stream": networkV,
	"GET /api/cnp":                 networkV,
	"GET /api/cnp/{name}":          networkV,
	"POST /api/cnp":                networkM,
	"PUT /api/cnp/{name}":          networkM,
	"DELETE /api/cnp/{name}":       networkM,

	"GET /api/vap":                    admitV,
	"GET /api/vap/{name}":             admitV,
	"GET /api/vap-bindings":           admitV,
	"GET /api/vap-bindings/{name}":    admitV,
	"POST /api/vap":                   admitM,
	"PUT /api/vap/{name}":             admitM,
	"DELETE /api/vap/{name}":          admitM,
	"POST /api/vap-bindings":          admitM,
	"PUT /api/vap-bindings/{name}":    admitM,
	"DELETE /api/vap-bindings/{name}": admitM,

	"GET /api/quarantine":                      quarV,
	"POST /api/quarantine":                     quarM,
	"DELETE /api/quarantine/{namespace}/{pod}": quarM,

	"GET /api/events/stream":           eventsV,
	"GET /api/admission-events":        eventsV,
	"GET /api/admission-events/stream": eventsV,
	"GET /api/security-events":         eventsV,
	"GET /api/security-events/stream":  eventsV,
	"GET /api/tetragon/agents":         eventsV,
	"GET /api/ingestion/health":        eventsV,

	"GET /api/security-events/retention":  retentionV,
	"GET /api/admission-events/retention": retentionV,

	"GET /api/vulnerabilities":                           vulnV,
	"GET /api/vulnerabilities/{namespace}/{kind}/{name}": vulnV,
	"GET /api/registries":                                vulnV,
	"GET /api/registries/{id}/images":                    vulnV,
	"GET /api/registries/{id}/findings":                  vulnV,
	"POST /api/registries":                               vulnM,
	"POST /api/registries/test":                          vulnM,
	"PUT /api/registries/{id}":                           vulnM,
	"DELETE /api/registries/{id}":                        vulnM,
	"POST /api/registries/{id}/scan":                     vulnM,

	"GET /api/alerts":          notifyV,
	"GET /api/rsyslog":         notifyV,
	"POST /api/alerts/test":    notifyM,
	"POST /api/alerts":         notifyM,
	"PUT /api/alerts/{id}":     notifyM,
	"DELETE /api/alerts/{id}":  notifyM,
	"POST /api/rsyslog/test":   notifyM,
	"POST /api/rsyslog":        notifyM,
	"PUT /api/rsyslog/{id}":    notifyM,
	"DELETE /api/rsyslog/{id}": notifyM,

	"GET /api/audit":                       systemV,
	"GET /api/users":                       systemV,
	"GET /api/roles":                       systemV,
	"GET /api/settings/session-ttl":        systemV,
	"POST /api/users":                      systemM,
	"PUT /api/users/{username}/namespaces": systemM,
	"PUT /api/users/{username}/role":       systemM,
	"DELETE /api/users/{username}":         systemM,
	"POST /api/roles":                      systemM,
	"PUT /api/roles/{name}":                systemM,
	"DELETE /api/roles/{name}":             systemM,
	"PUT /api/settings/session-ttl":        systemM,
	"PUT /api/security-events/retention":   systemM,
	"PUT /api/admission-events/retention":  systemM,
}

// probe is a handler tree with one account, "probe", whose role the test
// rewrites between requests.
type probe struct {
	h     http.Handler
	roles *auth.RoleStore
	c     *http.Cookie
}

func newProbe(t *testing.T) probe {
	t.Helper()
	users := auth.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	roles := auth.NewRoleStore("")
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := roles.Create(auth.RoleDef{Name: "probe"}); err != nil {
		t.Fatal(err)
	}
	if err := users.Create("probe", "longenough", "probe", nil); err != nil {
		t.Fatal(err)
	}
	u, _ := users.Get("probe")
	token, err := auth.SignToken(secret, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return probe{New(Config{Users: users, Roles: roles, Secret: secret}), roles, &http.Cookie{Name: "sentinel_token", Value: token}}
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// refused reports whether the role turned the request away. Whatever the
// handler does once reached does not matter here, a panic on the stores this
// tree was built without included.
func (p probe) refused(t *testing.T, route string, perms auth.Permissions) bool {
	t.Helper()
	if err := p.roles.Update("probe", perms); err != nil {
		t.Fatal(err)
	}
	method, pattern, _ := strings.Cut(route, " ")
	// A stream would otherwise wait for events that never come.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(method, pathParam.ReplaceAllString(pattern, "x"), strings.NewReader("{}")).WithContext(ctx)
	req.AddCookie(p.c)
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, req)
	return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), roleRefusal)
}

func allAt(l auth.Level) auth.Permissions {
	out := auth.Permissions{}
	for _, a := range auth.Areas {
		out[a] = l
	}
	return out
}

func below(l auth.Level) auth.Level {
	if l == auth.LevelManage {
		return auth.LevelView
	}
	return auth.LevelNone
}

func TestEveryRouteDeclaresAPermission(t *testing.T) {
	p := newProbe(t)
	seen := map[string]bool{}
	err := chi.Walk(p.h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if !strings.HasPrefix(route, "/api/") || publicRoutes[key] || strings.HasPrefix(route, webhookPath) {
			return nil
		}
		seen[key] = true
		if !openRoutes[key] && routePerms[key] == nil {
			t.Errorf("%s is routed and says nowhere what role it needs: add it to routePerms or openRoutes", key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key := range routePerms {
		if !seen[key] {
			t.Errorf("%s is in routePerms and is not routed", key)
		}
	}
	for key := range openRoutes {
		if !seen[key] {
			t.Errorf("%s is in openRoutes and is not routed", key)
		}
	}
}

func TestARouteAsksForItsAreaAndLevel(t *testing.T) {
	p := newProbe(t)
	for route, perms := range routePerms {
		// Everything but what the route asks for is not enough, however much.
		short := allAt(auth.LevelManage)
		for _, need := range perms {
			short[need.area] = below(need.level)
		}
		if !p.refused(t, route, short) {
			t.Errorf("%s: let through without %v", route, perms)
		}
		// Any one of what it asks for, and nothing else, is enough. A stream is
		// not asked: reached, it reads the cluster on a goroutine of its own, and
		// this tree has no cluster behind it.
		if strings.HasSuffix(route, "/stream") {
			continue
		}
		for _, need := range perms {
			only := allAt(auth.LevelNone)
			only[need.area] = need.level
			if p.refused(t, route, only) {
				t.Errorf("%s: refused with %s %s", route, need.area, need.level)
			}
		}
	}
	for route := range openRoutes {
		if p.refused(t, route, allAt(auth.LevelNone)) {
			t.Errorf("%s: refused to an account with no permissions", route)
		}
	}
}
