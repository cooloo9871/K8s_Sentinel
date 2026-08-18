package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Go does not complain about a function nobody calls, so a handler written and
// then never routed compiles, ships, and answers 404 in production. That is
// exactly how the quarantine endpoints reached a release with no route to them.
//
// Hitting each route without credentials separates the two failures: 401 means
// the route is there and the auth middleware turned it away, 404 means nothing
// is registered at that path at all.
func TestEveryRouteIsRegistered(t *testing.T) {
	h := New(Config{})

	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/quarantine"},
		{http.MethodPost, "/api/quarantine"},
		{http.MethodDelete, "/api/quarantine/demo/some-pod"},

		{http.MethodGet, "/api/policies"},
		{http.MethodPost, "/api/policies"},
		{http.MethodPut, "/api/policies/p"},
		{http.MethodPut, "/api/policies/p/mode"},
		{http.MethodDelete, "/api/policies/p"},
		{http.MethodGet, "/api/mode"},
		{http.MethodPut, "/api/mode"},
		{http.MethodPost, "/api/selector-preview"},

		{http.MethodGet, "/api/cnp"},
		{http.MethodPost, "/api/cnp"},
		{http.MethodPut, "/api/cnp/c"},
		{http.MethodDelete, "/api/cnp/c"},

		{http.MethodGet, "/api/vap"},
		{http.MethodPost, "/api/vap"},
		{http.MethodGet, "/api/vap-bindings"},
		{http.MethodPost, "/api/vap-bindings"},

		{http.MethodGet, "/api/security-events"},
		{http.MethodGet, "/api/security-events/retention"},
		{http.MethodPut, "/api/security-events/retention"},
		{http.MethodGet, "/api/admission-events"},
		{http.MethodGet, "/api/network-topology"},
		{http.MethodGet, "/api/cilium/status"},

		{http.MethodGet, "/api/alerts"},
		{http.MethodPost, "/api/alerts"},
		{http.MethodGet, "/api/rsyslog"},
		{http.MethodPost, "/api/rsyslog"},
		{http.MethodGet, "/api/users"},
		{http.MethodPost, "/api/users"},
		{http.MethodGet, "/api/settings/session-ttl"},
		{http.MethodPut, "/api/settings/session-ttl"},
		{http.MethodGet, "/api/templates"},
		{http.MethodGet, "/api/namespaces"},
		{http.MethodGet, "/api/auth/me"},
	}

	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(r.method, r.path, nil))
			if w.Code == http.StatusNotFound {
				t.Errorf("404 — no route registered, so the handler is unreachable")
			}
		})
	}
}

// The two public routes must stay public: the audit webhook is called by the
// kube-apiserver, which has no session, and logout has to work with a token the
// middleware would reject.
func TestThePublicRoutesNeedNoSession(t *testing.T) {
	h := New(Config{})
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/login"},
		{http.MethodPost, "/api/auth/logout"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(r.method, r.path, nil))
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
			t.Errorf("%s %s returned %d — it must not need a session", r.method, r.path, w.Code)
		}
	}
}
