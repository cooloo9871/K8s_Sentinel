package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func vapStore() *k8s.Store {
	g := "admissionregistration.k8s.io"
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: g, Version: "v1", Resource: "validatingadmissionpolicies"}:       "ValidatingAdmissionPolicyList",
		{Group: g, Version: "v1", Resource: "validatingadmissionpolicybindings"}: "ValidatingAdmissionPolicyBindingList",
	})
	return k8s.NewStore(client, nil, nil, "")
}

func policyYAML(name, extra string) string {
	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ` + name + `
spec:
  failurePolicy: Fail
` + extra + `  matchConstraints:
    resourceRules:
      - apiGroups: ["*"]
        apiVersions: ["*"]
        operations: [CREATE, UPDATE]
        resources: ["*"]
  validations:
    - expression: "true"
`
}

func bindingYAML(name, policy, selector string) string {
	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ` + name + `
spec:
  policyName: ` + policy + `
  validationActions: [Deny]
` + selector
}

func only(namespaces ...string) string {
	out := "  matchResources:\n    namespaceSelector:\n      matchExpressions:\n        - key: kubernetes.io/metadata.name\n          operator: In\n          values:\n"
	for _, ns := range namespaces {
		out += "            - " + ns + "\n"
	}
	return out
}

func status(err error) int {
	var r *refusal
	if errors.As(err, &r) {
		return r.status
	}
	if err != nil {
		return -1
	}
	return 0
}

// write does what the handlers do for an account limited to namespaces.
func write(t *testing.T, s *k8s.Store, sc scope, kind, raw string) error {
	t.Helper()
	ctx := context.Background()
	if kind == "policy" {
		out := raw
		if !sc.cluster() {
			var err error
			if out, err = limitPolicy(ctx, s, sc, raw); err != nil {
				return err
			}
		}
		return s.ApplyVAPRaw(ctx, out, "tester")
	}
	out := raw
	if !sc.cluster() {
		var err error
		if out, err = limitBinding(ctx, s, sc, raw); err != nil {
			return err
		}
	}
	return s.ApplyVAPBindingRaw(ctx, out, "tester")
}

func TestALimitedAccountsPolicyIsMarkedAndKeptToNamespacedResources(t *testing.T) {
	s, ctx := vapStore(), context.Background()
	teamA := scope{"team-a"}
	if err := write(t, s, teamA, "policy", policyYAML("a-rule", "")); err != nil {
		t.Fatal(err)
	}
	rec, err := s.GetVAP(ctx, "a-rule")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Namespaces) != 1 || rec.Namespaces[0] != "team-a" {
		t.Errorf("marked for %v, want [team-a]", rec.Namespaces)
	}
	// Without this the rule would be enforced on nodes and cluster roles
	// whatever namespaces its binding names.
	if !strings.Contains(rec.RawYAML, "scope: Namespaced") {
		t.Errorf("the policy can still match cluster-scoped resources:\n%s", rec.RawYAML)
	}

	// The whole cluster's admin saving it from the form, which writes neither
	// the mark nor the scope, leaves it the team's and as narrow.
	if err := write(t, s, scope{}, "policy", policyYAML("a-rule", "")); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.GetVAP(ctx, "a-rule")
	if len(rec.Namespaces) != 1 || !strings.Contains(rec.RawYAML, "scope: Namespaced") {
		t.Errorf("a save by the cluster's admin took the policy from its team: %v\n%s", rec.Namespaces, rec.RawYAML)
	}
}

func TestALimitedAccountCannotTouchOtherPolicies(t *testing.T) {
	s, ctx := vapStore(), context.Background()
	teamA, teamB := scope{"team-a"}, scope{"team-b"}
	if err := write(t, s, scope{}, "policy", policyYAML("cluster-rule", "")); err != nil {
		t.Fatal(err)
	}
	if err := write(t, s, teamB, "policy", policyYAML("b-rule", "")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cluster-rule", "b-rule"} {
		// Told that the name is taken, since nothing it can see would say so.
		err := write(t, s, teamA, "policy", policyYAML(name, ""))
		if got := status(err); got != http.StatusConflict || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("overwriting %s = %d %v, want 409 saying it already exists", name, got, err)
		}
	}
	// Claiming namespaces it does not have gets it its own.
	claimed := strings.Replace(policyYAML("a-rule", ""), "  name: a-rule\n", "  name: a-rule\n  annotations:\n    sentinel.io/namespaces: team-a,team-b\n", 1)
	if err := write(t, s, teamA, "policy", claimed); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.GetVAP(ctx, "a-rule"); len(rec.Namespaces) != 1 || rec.Namespaces[0] != "team-a" {
		t.Errorf("marked for %v, want [team-a]", rec.Namespaces)
	}
	// Parameters of any kind would let a refusal message read out an object.
	secret := "  paramKind:\n    apiVersion: v1\n    kind: Secret\n"
	if got := status(write(t, s, teamA, "policy", policyYAML("reads-secrets", secret))); got != http.StatusForbidden {
		t.Errorf("a policy taking Secrets as parameters = %d, want 403", got)
	}
	gate := "  paramKind:\n    apiVersion: sentinel.io/v1\n    kind: VulnerabilityGate\n"
	if err := write(t, s, teamA, "policy", policyYAML("vuln-limit", gate)); err != nil {
		t.Errorf("a vulnerability rule was refused: %v", err)
	}
}

// A binding left pointing at a name nobody has yet would enforce whatever is
// then made under it, wherever the binding points.
func TestALimitedAccountCannotFillAWaitingBinding(t *testing.T) {
	s := vapStore()
	if err := write(t, s, scope{}, "binding", bindingYAML("everywhere", "not-made-yet", "")); err != nil {
		t.Fatal(err)
	}
	if got := status(write(t, s, scope{"team-a"}, "policy", policyYAML("not-made-yet", ""))); got != http.StatusConflict {
		t.Errorf("status = %d, want 409", got)
	}
}

func TestALimitedAccountsBindingNamesItsNamespaces(t *testing.T) {
	s, ctx := vapStore(), context.Background()
	both, teamA := scope{"team-a", "team-b"}, scope{"team-a"}
	if err := write(t, s, teamA, "policy", policyYAML("a-rule", "")); err != nil {
		t.Fatal(err)
	}
	if err := write(t, s, scope{}, "policy", policyYAML("cluster-rule", "")); err != nil {
		t.Fatal(err)
	}
	label := "  matchResources:\n    namespaceSelector:\n      matchLabels:\n        kubernetes.io/metadata.name: team-a\n"
	for name, c := range map[string]struct {
		sc       scope
		policy   string
		selector string
		want     int
	}{
		"by name":                    {teamA, "a-rule", only("team-a"), 0},
		"by name, as a label":        {teamA, "a-rule", label, 0},
		"everywhere":                 {teamA, "a-rule", "", http.StatusForbidden},
		"another namespace":          {teamA, "a-rule", only("kube-system"), http.StatusForbidden},
		"one of its own and one not": {teamA, "a-rule", only("team-a", "team-b"), http.StatusForbidden},
		// The account has team-b; the policy is not for it, and its other
		// admins could not see what a change to it would reach.
		"a namespace the policy is not for": {both, "a-rule", only("team-b"), http.StatusForbidden},
		"all but some":                      {teamA, "a-rule", strings.Replace(only("kube-system"), "In", "NotIn", 1), http.StatusForbidden},
		// A label of the namespace's own is its owner's to change.
		"by another label":           {teamA, "a-rule", "  matchResources:\n    namespaceSelector:\n      matchLabels:\n        team: a\n", http.StatusForbidden},
		"by name and another label":  {teamA, "a-rule", "  matchResources:\n    namespaceSelector:\n      matchLabels:\n        kubernetes.io/metadata.name: team-a\n        team: a\n", 0 + http.StatusForbidden},
		"the cluster's policy":       {teamA, "cluster-rule", only("team-a"), http.StatusForbidden},
		"a policy that is not there": {teamA, "nothing", only("team-a"), http.StatusForbidden},
		"parameters from elsewhere":  {teamA, "a-rule", "  paramRef:\n    name: x\n    namespace: kube-system\n" + only("team-a"), http.StatusForbidden},
		"the vulnerability counts":   {teamA, "a-rule", "  paramRef:\n    name: sentinel-vulnerability-gate\n    parameterNotFoundAction: Allow\n" + only("team-a"), 0},
	} {
		if got := status(write(t, s, c.sc, "binding", bindingYAML("b", c.policy, c.selector))); got != c.want {
			t.Errorf("%s: status = %d, want %d", name, got, c.want)
		}
	}
	rec, err := s.GetVAPBinding(ctx, "b")
	if err != nil || len(rec.Namespaces) != 1 || rec.Namespaces[0] != "team-a" {
		t.Errorf("binding held to %v (%v), want [team-a]", rec.Namespaces, err)
	}

	// The cluster's binding to the same namespace is not the team's to change.
	if err := write(t, s, scope{}, "binding", bindingYAML("imposed", "cluster-rule", only("team-a"))); err != nil {
		t.Fatal(err)
	}
	if got := status(write(t, s, teamA, "binding", bindingYAML("imposed", "a-rule", only("team-a")))); got != http.StatusConflict {
		t.Errorf("overwriting the cluster's binding = %d, want 409", got)
	}
	if rec, _ := s.GetVAPBinding(ctx, "imposed"); teamA.manages(rec.Namespaces) {
		t.Error("the cluster's binding to team-a is listed as the team's")
	}
}

func TestManages(t *testing.T) {
	teamA := scope{"team-a"}
	for _, c := range []struct {
		namespaces []string
		want       bool
	}{
		{nil, false},
		{[]string{"team-a"}, true},
		{[]string{"team-a", "team-b"}, false},
		{[]string{"team-b"}, false},
	} {
		if got := teamA.manages(c.namespaces); got != c.want {
			t.Errorf("manages(%v) = %v, want %v", c.namespaces, got, c.want)
		}
	}
	if !(scope{}).manages(nil) {
		t.Error("an account with no limit manages everything")
	}
}

// A create under a name that is taken is refused for everyone, and an edit of
// the same name still goes through.
func TestCreatingUnderATakenNameIsRefused(t *testing.T) {
	s := vapStore()
	router := chi.NewRouter()
	router.Post("/vap", applyVAP(s, func() {}))
	router.Put("/vap/{name}", applyVAP(s, func() {}))
	router.Post("/vap-bindings", applyVAPBinding(s))
	router.Put("/vap-bindings/{name}", applyVAPBinding(s))

	send := func(method, path, raw string, namespaces ...string) (int, string) {
		body, _ := json.Marshal(map[string]string{"rawYaml": raw})
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "tester", Role: "admin", Namespaces: namespaces}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	for _, who := range [][]string{nil, {"team-a"}} {
		policy, binding := "rule-"+strings.Join(who, ""), "bind-"+strings.Join(who, "")
		if code, msg := send("POST", "/vap", policyYAML(policy, ""), who...); code != http.StatusOK {
			t.Fatalf("%v: first create = %d %s", who, code, msg)
		}
		if code, msg := send("POST", "/vap", policyYAML(policy, ""), who...); code != http.StatusConflict || !strings.Contains(msg, "already exists. Choose another name.") {
			t.Errorf("%v: second create = %d %q, want 409 saying it already exists", who, code, msg)
		}
		if code, msg := send("PUT", "/vap/"+policy, policyYAML(policy, ""), who...); code != http.StatusOK {
			t.Errorf("%v: edit = %d %s", who, code, msg)
		}
		raw := bindingYAML(binding, policy, only("team-a"))
		if code, msg := send("POST", "/vap-bindings", raw, who...); code != http.StatusOK {
			t.Fatalf("%v: first binding = %d %s", who, code, msg)
		}
		if code, msg := send("POST", "/vap-bindings", raw, who...); code != http.StatusConflict || !strings.Contains(msg, "already exists. Choose another name.") {
			t.Errorf("%v: second binding = %d %q, want 409 saying it already exists", who, code, msg)
		}
		if code, msg := send("PUT", "/vap-bindings/"+binding, raw, who...); code != http.StatusOK {
			t.Errorf("%v: binding edit = %d %s", who, code, msg)
		}
	}
}
