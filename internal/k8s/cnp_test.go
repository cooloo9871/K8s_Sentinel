package k8s

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func recordFromYAML(t *testing.T, y string) CNPRecord {
	t.Helper()
	j, err := yaml.YAMLToJSON([]byte(y))
	if err != nil {
		t.Fatalf("bad test YAML: %v", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(j, &obj.Object); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return toCNPRecord(*obj, "namespace")
}

// A deny-only policy that explicitly opts out of default-deny must not be
// reported as locking the workload down — the operator would otherwise believe
// all egress is blocked when only one destination is.
func TestDefaultDenyRespectsExplicitOptOut(t *testing.T) {
	r := recordFromYAML(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: deny-tg-to-echo, namespace: net-lab}
spec:
  endpointSelector: {matchLabels: {app: traffic-generator}}
  enableDefaultDeny: {egress: false, ingress: false}
  egressDeny:
    - toEndpoints: [{matchLabels: {app: echo-server}}]
`)
	if r.DefaultDeny != "" {
		t.Errorf("DefaultDeny = %q, want empty — the policy opts out", r.DefaultDeny)
	}
	if r.EgressRules != 1 {
		t.Errorf("EgressRules = %d, want 1", r.EgressRules)
	}
	if r.IngressRules != 0 {
		t.Errorf("IngressRules = %d, want 0", r.IngressRules)
	}
	if r.Selector != "app=traffic-generator" {
		t.Errorf("Selector = %q", r.Selector)
	}
}

// Without the field, Cilium derives default-deny from the presence of rules.
func TestDefaultDenyDerivedFromRules(t *testing.T) {
	r := recordFromYAML(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: isolate, namespace: default}
spec:
  endpointSelector: {}
  ingress:
    - fromEndpoints: [{}]
`)
	if r.DefaultDeny != "ingress" {
		t.Errorf("DefaultDeny = %q, want ingress", r.DefaultDeny)
	}
	if r.Selector != "all endpoints" {
		t.Errorf("Selector = %q, want 'all endpoints'", r.Selector)
	}
}

// An L7 rule set must be flagged, and both directions reported together.
func TestBothDirectionsAndL7(t *testing.T) {
	r := recordFromYAML(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: l7, namespace: default}
spec:
  endpointSelector: {matchLabels: {app: api}}
  ingress:
    - fromEntities: [all]
      toPorts:
        - ports: [{port: "80", protocol: TCP}]
          rules: {http: [{}]}
  egress:
    - toEntities: [all]
`)
	if r.DefaultDeny != "both" {
		t.Errorf("DefaultDeny = %q, want both", r.DefaultDeny)
	}
	if !r.HasL7 {
		t.Error("HasL7 = false, want true")
	}
	if r.IngressRules != 1 || r.EgressRules != 1 {
		t.Errorf("rules = in %d / out %d, want 1/1", r.IngressRules, r.EgressRules)
	}
}
