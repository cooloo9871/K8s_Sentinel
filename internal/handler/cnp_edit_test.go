package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
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

// A create under a name that is taken is refused; the same manifest sent as an
// edit still saves.
func TestCreatingANetworkPolicyUnderATakenNameIsRefused(t *testing.T) {
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}:            "CiliumNetworkPolicyList",
		{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}: "CiliumClusterwideNetworkPolicyList",
	})
	store := k8s.NewStore(client, nil, nil, "")
	post := func(raw string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"rawYaml": raw})
		w := httptest.NewRecorder()
		applyCNP(store)(w, withClaims(httptest.NewRequest(http.MethodPost, "/api/cnp", bytes.NewReader(body)), "admin", auth.RoleAdmin))
		return w
	}
	namespaced := "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: deny-egress\n  namespace: net-lab\nspec:\n  endpointSelector: {}\n"
	clusterwide := "apiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: deny-egress\nspec:\n  endpointSelector: {}\n"
	for _, raw := range []string{namespaced, clusterwide} {
		if w := post(raw); w.Code != http.StatusNoContent {
			t.Fatalf("first create = %d %s", w.Code, w.Body.String())
		}
		if w := post(raw); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "already exists") {
			t.Errorf("second create = %d %s, want 409 saying it already exists", w.Code, w.Body.String())
		}
	}
	// The same name in another namespace is another policy.
	if w := post(strings.Replace(namespaced, "net-lab", "other", 1)); w.Code != http.StatusNoContent {
		t.Errorf("same name elsewhere = %d %s", w.Code, w.Body.String())
	}
	w, r := putCNP("deny-egress", "net-lab", "namespace", namespaced)
	applyCNP(store)(w, withClaims(r, "admin", auth.RoleAdmin))
	if w.Code != http.StatusNoContent {
		t.Errorf("edit = %d %s", w.Code, w.Body.String())
	}
}

// The policy that isolates quarantined pods is not written from the policy
// list: edited there it would let them all back on the network while every page
// still called them quarantined, and an account that manages network policy
// could do with it what only quarantine's own permission allows.
func TestTheQuarantinePolicyIsNotWrittenFromThePolicyList(t *testing.T) {
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}:            "CiliumNetworkPolicyList",
		{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}: "CiliumClusterwideNetworkPolicyList",
	})
	store := k8s.NewStore(client, nil, nil, "")
	open := "apiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: " + k8s.QuarantinePolicyName + "\nspec:\n  endpointSelector:\n    matchLabels:\n      nobody: here\n"

	// Made under that name it would stand in for the real one.
	body, _ := json.Marshal(map[string]string{"rawYaml": open})
	w := httptest.NewRecorder()
	applyCNP(store)(w, withClaims(httptest.NewRequest(http.MethodPost, "/api/cnp", bytes.NewReader(body)), "admin", auth.RoleAdmin))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Quarantine page") {
		t.Errorf("create = %d %s, want 409 pointing at the Quarantine page", w.Code, w.Body.String())
	}
	w, r := putCNP(k8s.QuarantinePolicyName, "", "cluster", open)
	applyCNP(store)(w, withClaims(r, "admin", auth.RoleAdmin))
	if w.Code != http.StatusConflict {
		t.Errorf("edit = %d %s, want 409", w.Code, w.Body.String())
	}
	if _, err := store.GetCNP(context.Background(), "cluster", "", k8s.QuarantinePolicyName); err == nil {
		t.Error("a policy was written under the quarantine policy's name")
	}
	// A namespaced policy that happens to share the name is an ordinary policy.
	body, _ = json.Marshal(map[string]string{"rawYaml": "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: " + k8s.QuarantinePolicyName + "\n  namespace: net-lab\nspec:\n  endpointSelector: {}\n"})
	w = httptest.NewRecorder()
	applyCNP(store)(w, withClaims(httptest.NewRequest(http.MethodPost, "/api/cnp", bytes.NewReader(body)), "admin", auth.RoleAdmin))
	if w.Code != http.StatusNoContent {
		t.Errorf("a namespaced policy of the same name = %d %s", w.Code, w.Body.String())
	}
}
