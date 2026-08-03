package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// emptyPolicyClient is a dynamic client holding no Cilium policies, for tests
// that only care about the pod side of the attribution cache. The fake client
// needs the list kinds declared for every CRD the loader queries.
func emptyPolicyClient() *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		cnpGVR:  "CiliumNetworkPolicyList",
		ccnpGVR: "CiliumClusterwideNetworkPolicyList",
	})
}

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

// Each spec in a `specs[]` policy carries its own endpointSelector and its own
// rules. Merging them let one spec's labels win, attributing a denial to a
// policy whose matching spec had no rules in that direction at all.
func TestSpecsListEvaluatesEachSpecSeparately(t *testing.T) {
	d := attributionData{
		podLabels: map[string]map[string]string{
			"demo/api-1": {"app": "api"},
		},
		policies: []policySelector{
			// spec[0]: governs app=web on ingress
			{Name: "multi", Namespace: "demo", MatchLabels: map[string]string{"app": "web"}, HasIngress: true},
			// spec[1]: governs app=api on egress
			{Name: "multi", Namespace: "demo", MatchLabels: map[string]string{"app": "api"}, HasEgress: true},
		},
	}
	s := &Store{attrData: &d, attrExpiry: time.Now().Add(time.Minute)}

	if got := s.AttributePolicyDenial(context.Background(), "demo", "api-1", "egress"); got != "multi" {
		t.Errorf("egress = %q, want multi (spec[1] governs app=api on egress)", got)
	}
	// app=api is only selected by the egress spec, so an ingress denial is not this policy.
	if got := s.AttributePolicyDenial(context.Background(), "demo", "api-1", "ingress"); got != "" {
		t.Errorf("ingress = %q, want empty — no spec governs app=api on ingress", got)
	}
}

// Both specs matching must not name the same policy twice.
func TestMatchingSpecsNameThePolicyOnce(t *testing.T) {
	d := attributionData{
		podLabels: map[string]map[string]string{"demo/api-1": {"app": "api"}},
		policies: []policySelector{
			{Name: "multi", Namespace: "demo", MatchLabels: map[string]string{"app": "api"}, HasEgress: true},
			{Name: "multi", Namespace: "demo", MatchLabels: map[string]string{"app": "api"}, HasEgress: true},
		},
	}
	s := &Store{attrData: &d, attrExpiry: time.Now().Add(time.Minute)}
	if got := s.AttributePolicyDenial(context.Background(), "demo", "api-1", "egress"); got != "multi" {
		t.Errorf("got %q, want multi listed once", got)
	}
}

// With no direction to go on, a policy carrying no rules at all cannot be
// responsible for anything and must not be named.
func TestUnknownDirectionSkipsRulelessPolicies(t *testing.T) {
	d := attributionData{
		podLabels: map[string]map[string]string{"demo/api-1": {"app": "api"}},
		policies: []policySelector{
			{Name: "empty", Namespace: "demo", MatchLabels: map[string]string{"app": "api"}},
		},
	}
	s := &Store{attrData: &d, attrExpiry: time.Now().Add(time.Minute)}
	if got := s.AttributePolicyDenial(context.Background(), "demo", "api-1", ""); got != "" {
		t.Errorf("got %q, want empty — the policy has no rules", got)
	}
}

// The container name has to come from the Kubernetes API, because Hubble flows
// do not carry one. Attributed only for a single-container pod: with several,
// the flow does not say which one opened the connection.
func TestPodContainerListsEveryContainer(t *testing.T) {
	typed := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "traffic-generator-9b649846d-bxqfc", Namespace: "net-lab"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traffic-generator"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "sidecar-pod", Namespace: "net-lab"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
		},
	)
	s := &Store{typed: typed, client: emptyPolicyClient()}

	got := s.PodContainer(context.Background(), "net-lab", "traffic-generator-9b649846d-bxqfc")
	if got != "traffic-generator" {
		t.Errorf("container = %q, want traffic-generator", got)
	}
	// Every container is a candidate: they share one network namespace, so the
	// flow cannot say which opened the connection.
	if got := s.PodContainer(context.Background(), "net-lab", "sidecar-pod"); got != "app, proxy" {
		t.Errorf("multi-container pod = %q, want \"app, proxy\"", got)
	}
	if got := s.PodContainer(context.Background(), "net-lab", "gone"); got != "" {
		t.Errorf("unknown pod = %q, want empty", got)
	}
}

// The end-to-end path for the reported case: an egress denial Hubble correlated
// to deny-tg-to-echo must name the source pod and its container.
func TestDenialEventCarriesTheSourceContainer(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid flow")
	}
	typed := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "traffic-generator-9b649846d-bxqfc", Namespace: "net-lab"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traffic-generator"}}},
	})
	s := &Store{typed: typed, client: emptyPolicyClient()}

	evt, ok := s.SynthesizePolicyDenyEvent(context.Background(), f)
	if !ok {
		t.Fatal("no event synthesized")
	}
	if evt.Pod != "traffic-generator-9b649846d-bxqfc" {
		t.Errorf("pod = %q, want the source", evt.Pod)
	}
	if evt.Container != "traffic-generator" {
		t.Errorf("container = %q, want traffic-generator", evt.Container)
	}
	if evt.PolicyName != "deny-tg-to-echo" {
		t.Errorf("policy = %q, want deny-tg-to-echo", evt.PolicyName)
	}
}
