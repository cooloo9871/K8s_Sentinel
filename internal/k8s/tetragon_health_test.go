package k8s

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// The failure this whole feature exists for: a Tetragon pod is Ready, but
// Sentinel's gRPC stream to it never connected. GetTetragonAgents must report
// the agent as Ready yet ingestion-down, not silently healthy.
func TestTetragonAgentsFoldInIngestionHealth(t *testing.T) {
	ns := tetragonNamespace()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tetragon-xyz",
			Namespace: ns,
			Labels:    map[string]string{"app.kubernetes.io/name": "tetragon"},
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.1",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "tetragon", Ready: true},
			},
		},
	}
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(pod), nil, "")
	// The stream to node w1 failed to connect.
	store.Ingestion().MarkTetragonError("w1", fmt.Errorf("connection refused"))

	agents, err := store.GetTetragonAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("got %d agents, want 1", len(agents))
	}
	a := agents[0]
	if !a.Ready {
		t.Error("pod is Ready and should report so")
	}
	if !a.IngestObserved || a.IngestConnected {
		t.Errorf("ingest observed=%v connected=%v, want observed=true connected=false",
			a.IngestObserved, a.IngestConnected)
	}
	if a.IngestFailures != 1 || a.IngestLastError != "connection refused" {
		t.Errorf("ingest failures=%d err=%q, want 1/%q", a.IngestFailures, a.IngestLastError, "connection refused")
	}
}

// An agent with no recorded stream attempt yet reports IngestObserved=false, so
// the UI can distinguish "not measured" from "measured and down".
func TestTetragonAgentsUnobservedIngestion(t *testing.T) {
	ns := tetragonNamespace()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tetragon-abc",
			Namespace: ns,
			Labels:    map[string]string{"app.kubernetes.io/name": "tetragon"},
		},
		Spec: corev1.PodSpec{NodeName: "w2"},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			PodIP:             "10.0.0.2",
			ContainerStatuses: []corev1.ContainerStatus{{Name: "tetragon", Ready: true}},
		},
	}
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(pod), nil, "")

	agents, err := store.GetTetragonAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].IngestObserved {
		t.Errorf("want one agent with IngestObserved=false, got %+v", agents)
	}
}
