package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// putCNP builds the PUT the UI sends when saving an edit: the name in the URL,
// the namespace and scope the policy opened from in the query.
func putCNP(name, namespace, scope, rawYaml string) (*httptest.ResponseRecorder, *http.Request) {
	body := strings.NewReader(`{"rawYaml": ` + strings.ReplaceAll(
		`"`+strings.ReplaceAll(rawYaml, "\n", `\n`)+`"`, "\t", " ") + `}`)
	r := httptest.NewRequest(http.MethodPut,
		"/api/cnp/"+name+"?namespace="+namespace+"&scope="+scope, body)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("name", name)
	return httptest.NewRecorder(), r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// Renaming is refused by checkManifestName; moving does the same damage
// sideways. An edit that changes metadata.namespace would create a copy in the
// new namespace and leave the original in place — while the UI says the edit
// was saved. Both refusals fire before the store is touched, which is what
// lets these tests pass a nil one.
func TestEditingRejectsANamespaceMove(t *testing.T) {
	w, r := putCNP("deny-egress", "net-lab", "namespace",
		"kind: CiliumNetworkPolicy\nmetadata:\n  name: deny-egress\n  namespace: other\n")
	applyCNP(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the edit moved the policy to another namespace", w.Code)
	}
	if !strings.Contains(w.Body.String(), "namespace") {
		t.Errorf("the refusal does not say it is about the namespace: %s", w.Body.String())
	}
}

func TestEditingRejectsARenameEndToEnd(t *testing.T) {
	w, r := putCNP("deny-egress", "net-lab", "namespace",
		"kind: CiliumNetworkPolicy\nmetadata:\n  name: something-else\n  namespace: net-lab\n")
	applyCNP(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the edit renamed the policy", w.Code)
	}
}

// The third way to the same failure: keeping the name, dropping the namespace
// and switching the kind. A namespaced policy edited into a cluster-wide one
// slips past both guards above and leaves the original behind all the same.
func TestEditingRejectsAKindChange(t *testing.T) {
	w, r := putCNP("deny-egress", "net-lab", "namespace",
		"kind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: deny-egress\n")
	applyCNP(nil)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the edit changed the policy's kind", w.Code)
	}
}
