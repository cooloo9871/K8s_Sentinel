package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// putPolicy builds the PUT the UI sends when saving a tracing-policy edit: the
// name in the URL, the namespace it opened from in the query ("" for a
// cluster-scoped policy), the request body as given.
func putPolicy(name, namespace, body string) (*httptest.ResponseRecorder, *http.Request) {
	r := httptest.NewRequest(http.MethodPut,
		"/api/policies/"+name+"?namespace="+namespace, strings.NewReader(body))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("name", name)
	return httptest.NewRecorder(), r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// The same three-way guard the CNP editor has: an edit whose manifest or form
// renames the policy, moves it to another namespace, or switches it between
// TracingPolicy and TracingPolicyNamespaced would create a copy and leave the
// original in place — while the UI said the edit was saved. Every refusal
// fires before the store is touched, which is what lets these tests pass a
// nil one.
func TestPolicyEditRejectsARenameInYAML(t *testing.T) {
	w, r := putPolicy("watch-exec", "", `{"source":"yaml","rawYaml":"kind: TracingPolicy\nmetadata:\n  name: something-else\n"}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the manifest renamed the policy", w.Code)
	}
}

func TestPolicyEditRejectsARenameInTheForm(t *testing.T) {
	w, r := putPolicy("watch-exec", "", `{"source":"form","form":{"name":"something-else"}}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the form renamed the policy", w.Code)
	}
}

func TestPolicyEditRejectsANamespaceMove(t *testing.T) {
	w, r := putPolicy("watch-exec", "net-lab", `{"source":"yaml","rawYaml":"kind: TracingPolicyNamespaced\nmetadata:\n  name: watch-exec\n  namespace: other\n"}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the manifest moved the policy to another namespace", w.Code)
	}

	w, r = putPolicy("watch-exec", "net-lab", `{"source":"form","form":{"name":"watch-exec","namespace":"other"}}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the form moved the policy to another namespace", w.Code)
	}
}

func TestPolicyEditRejectsAKindSwitch(t *testing.T) {
	// A namespaced policy edited into a cluster-wide one: name kept, namespace
	// dropped, kind switched.
	w, r := putPolicy("watch-exec", "net-lab", `{"source":"yaml","rawYaml":"kind: TracingPolicy\nmetadata:\n  name: watch-exec\n"}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the manifest switched the policy's kind", w.Code)
	}

	// And the form equivalent: clearing the namespace of a namespaced policy.
	w, r = putPolicy("watch-exec", "net-lab", `{"source":"form","form":{"name":"watch-exec","namespace":""}}`)
	updatePolicy(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the form cleared the policy's namespace", w.Code)
	}
}
