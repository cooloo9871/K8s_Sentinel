package k8s

import "testing"

// The allowlist policy that exposed the gap: it permits egress to port 80 only,
// so everything else is dropped by default-deny. Hubble reports no denying rule
// for those drops — the policy is only findable by asking which policy governs
// the pod.
func demoPolicies() attributionData {
	return attributionData{
		policies: []policySelector{
			{Name: "l4-rule", Namespace: "demo", MatchLabels: map[string]string{"app": "myservice"}, HasEgress: true},
			{Name: "deny-tg-to-echo", Namespace: "net-lab", MatchLabels: map[string]string{"app": "traffic-generator"}, HasEgress: true},
			{Name: "ingress-only", Namespace: "demo", MatchLabels: map[string]string{"app": "myservice"}, HasIngress: true},
			{Name: "ns-wide", Namespace: "demo", HasEgress: true}, // empty selector
			{Name: "expr-based", Namespace: "demo", Unevaluatable: true, HasEgress: true},
		},
		podLabels: map[string]map[string]string{
			"demo/myservice-abc":          {"app": "myservice"},
			"demo/other-pod":              {"app": "other"},
			"net-lab/traffic-generator-1": {"app": "traffic-generator"},
		},
	}
}

func attribute(d attributionData, ns, pod, dir string) string {
	var names []string
	labels, known := d.podLabels[ns+"/"+pod]
	if !known {
		return ""
	}
	for _, p := range d.policies {
		if dir == "egress" && !p.HasEgress {
			continue
		}
		if dir == "ingress" && !p.HasIngress {
			continue
		}
		if p.matches(ns, labels) {
			names = append(names, p.Name)
		}
	}
	return joinSorted(names)
}

func TestAttributionMatchesSelectorAndDirection(t *testing.T) {
	d := demoPolicies()

	// l4-rule and the namespace-wide policy both govern this pod's egress.
	// ingress-only is excluded by direction; expr-based is not evaluatable.
	if got := attribute(d, "demo", "myservice-abc", "egress"); got != "l4-rule, ns-wide" {
		t.Errorf("egress attribution = %q, want %q", got, "l4-rule, ns-wide")
	}
	// Only the ingress policy governs this direction.
	if got := attribute(d, "demo", "myservice-abc", "ingress"); got != "ingress-only" {
		t.Errorf("ingress attribution = %q, want ingress-only", got)
	}
	// A pod the selector does not match is only caught by the empty selector.
	if got := attribute(d, "demo", "other-pod", "egress"); got != "ns-wide" {
		t.Errorf("non-matching pod = %q, want ns-wide", got)
	}
}

// A namespaced policy must never be attributed to a pod in another namespace.
func TestAttributionRespectsNamespace(t *testing.T) {
	d := demoPolicies()
	if got := attribute(d, "net-lab", "traffic-generator-1", "egress"); got != "deny-tg-to-echo" {
		t.Errorf("attribution = %q, want deny-tg-to-echo only", got)
	}
}

// An unknown pod yields nothing, so no event names a policy we cannot verify.
func TestAttributionUnknownPod(t *testing.T) {
	d := demoPolicies()
	if got := attribute(d, "demo", "deleted-pod", "egress"); got != "" {
		t.Errorf("attribution = %q, want empty", got)
	}
}

// A cluster-wide policy (empty Namespace) governs pods in every namespace.
func TestAttributionClusterWide(t *testing.T) {
	d := attributionData{
		policies:  []policySelector{{Name: "cw", Namespace: "", HasEgress: true}},
		podLabels: map[string]map[string]string{"anywhere/p": {}},
	}
	if got := attribute(d, "anywhere", "p", "egress"); got != "cw" {
		t.Errorf("attribution = %q, want cw", got)
	}
}
