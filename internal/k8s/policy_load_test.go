package k8s

import (
	"context"
	"testing"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func agentPod(name, node, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tetragonNamespace(), Labels: map[string]string{"app.kubernetes.io/name": "tetragon"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
	}
}

// loadStore has two agents, which answer with the given policies by node.
func loadStore(t *testing.T, byNode map[string][]*tetragon.TracingPolicyStatus) *Store {
	t.Helper()
	prev := tracingPoliciesOn
	tracingPoliciesOn = func(_ context.Context, a podEndpoint) ([]*tetragon.TracingPolicyStatus, error) {
		return byNode[a.Node], nil
	}
	t.Cleanup(func() { tracingPoliciesOn = prev })
	return NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(
		agentPod("tetragon-a", "m1", "10.0.0.1"), agentPod("tetragon-b", "w1", "10.0.0.2")), nil, "")
}

func status(ns, name string, state tetragon.TracingPolicyState, err string) *tetragon.TracingPolicyStatus {
	return &tetragon.TracingPolicyStatus{Namespace: ns, Name: name, State: state, Error: err}
}

// The object in the cluster looks the same whether Tetragon took it or not.
func TestAPolicyAnAgentFailedToLoadIsMarked(t *testing.T) {
	enabled, failed := tetragon.TracingPolicyState_TP_STATE_ENABLED, tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR
	s := loadStore(t, map[string][]*tetragon.TracingPolicyStatus{
		"m1": {status("shop", "ok", enabled, ""), status("shop", "full", failed, "key too big for map"), status("", "wide", enabled, ""),
			status("shop", "one-node", enabled, ""), status("shop", "loading", tetragon.TracingPolicyState_TP_STATE_LOADING, "")},
		"w1": {status("shop", "ok", enabled, ""), status("shop", "full", failed, "key too big for map"), status("", "wide", enabled, ""),
			status("shop", "one-node", failed, "")},
	})
	records := []PolicyRecord{
		{Name: "ok", Namespace: "shop"}, {Name: "full", Namespace: "shop"}, {Name: "wide"},
		{Name: "one-node", Namespace: "shop"}, {Name: "loading", Namespace: "shop"}, {Name: "unknown", Namespace: "shop"},
	}
	s.MarkInactive(context.Background(), records)
	want := map[string]bool{"full": true, "one-node": true}
	for _, r := range records {
		if (r.Inactive != "") != want[r.Name] {
			t.Errorf("%s: inactive = %q", r.Name, r.Inactive)
		}
	}
	if records[1].Inactive != "key too big for map" {
		t.Errorf("reason = %q, want what Tetragon said", records[1].Inactive)
	}
	// Same name, another namespace: not the one that failed.
	other := []PolicyRecord{{Name: "full", Namespace: "other"}}
	s.MarkInactive(context.Background(), other)
	if other[0].Inactive != "" {
		t.Error("a policy of the same name in another namespace was marked")
	}
}

// With no agent to ask, nothing is known and nothing is claimed.
func TestNoAgentMarksNothing(t *testing.T) {
	s := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(), nil, "")
	records := []PolicyRecord{{Name: "p", Namespace: "shop"}}
	s.MarkInactive(context.Background(), records)
	if records[0].Inactive != "" {
		t.Error("a policy was called inactive with no agent to say so")
	}
}
