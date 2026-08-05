package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// requestNamed builds a PUT carrying the URL name the way chi would supply it.
func requestNamed(name string) (*httptest.ResponseRecorder, *http.Request) {
	r := httptest.NewRequest(http.MethodPut, "/api/cnp/"+name, nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("name", name)
	return httptest.NewRecorder(), r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// Both apply handlers took the object's name from the manifest and ignored the
// one in the URL, so renaming a policy in the editor created a second policy and
// left the original in place — while the UI said the edit was saved.
func TestEditingRejectsARenameInTheManifest(t *testing.T) {
	w, r := requestNamed("deny-egress")
	if checkManifestName(w, r, "metadata:\n  name: something-else\n") {
		t.Error("a manifest naming a different policy was accepted")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestEditingAcceptsTheMatchingName(t *testing.T) {
	w, r := requestNamed("deny-egress")
	if !checkManifestName(w, r, "metadata:\n  name: deny-egress\n") {
		t.Error("a manifest naming the policy being edited was rejected")
	}
}

// A create has no name in the URL to agree with.
func TestCreatingAcceptsAnyName(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/cnp", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, chi.NewRouteContext()))
	if !checkManifestName(httptest.NewRecorder(), r, "metadata:\n  name: anything\n") {
		t.Error("a create was rejected")
	}
}

// Unparseable YAML is the store's error to report, with its own message.
func TestUnparseableYAMLIsLeftToTheStore(t *testing.T) {
	w, r := requestNamed("deny-egress")
	if !checkManifestName(w, r, "\tnot: [valid") {
		t.Error("unusable YAML was rejected here instead of by the store")
	}
}
