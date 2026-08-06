package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func suspectPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "compromised", Namespace: "demo"},
		Spec:       corev1.PodSpec{NodeName: "w1"},
	}
}

func quarantineStore(objs ...*corev1.Pod) *Store {
	typed := k8sfake.NewSimpleClientset()
	for _, p := range objs {
		_, _ = typed.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{})
	}
	return NewStore(emptyPolicyClient(), typed, nil, "")
}

func TestQuarantineLabelsThePod(t *testing.T) {
	s := quarantineStore(suspectPod())

	if err := s.Quarantine(context.Background(), "demo", "compromised", "andy"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	p, err := s.typed.CoreV1().Pods("demo").Get(context.Background(), "compromised", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Labels[QuarantineLabel] != "true" {
		t.Errorf("label = %q, want true — nothing selects the pod without it", p.Labels[QuarantineLabel])
	}
	// The record travels with the object, so a Sentinel restart cannot lose it.
	if p.Annotations[quarantineByAnnotation] != "andy" {
		t.Errorf("quarantined-by = %q, want the operator who asked", p.Annotations[quarantineByAnnotation])
	}
	if p.Annotations[quarantineAtAnnotation] == "" {
		t.Error("no timestamp recorded")
	}
}

// Labelling a pod that nothing selects would report success and contain nothing,
// so the policy has to exist before the label goes on.
func TestQuarantineCreatesTheStandingPolicy(t *testing.T) {
	s := quarantineStore(suspectPod())

	if err := s.Quarantine(context.Background(), "demo", "compromised", "andy"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	got, err := s.client.Resource(ccnpGVR).Get(context.Background(), quarantinePolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the standing policy was not created: %v", err)
	}
	spec := got.Object["spec"].(map[string]any)

	sel := spec["endpointSelector"].(map[string]any)["matchLabels"].(map[string]any)
	if sel[QuarantineLabel] != "true" {
		t.Errorf("the policy selects %v, not the quarantine label", sel)
	}

	// Ingress from the node has to stay open. Without it the kubelet's probes
	// fail, the container is restarted, and the Deployment replaces the pod with
	// a fresh uncontained one — losing the containment and the evidence with it.
	ingress := spec["ingress"].([]any)[0].(map[string]any)["fromEntities"].([]any)
	var host bool
	for _, e := range ingress {
		if e == "host" {
			host = true
		}
	}
	if !host {
		t.Errorf("ingress allows %v — the kubelet's probes must still reach the pod", ingress)
	}

	// Egress denied outright: a deny beats any allow, so there is no way out.
	deny := spec["egressDeny"].([]any)[0].(map[string]any)["toEntities"].([]any)
	if len(deny) != 1 || deny[0] != "all" {
		t.Errorf("egressDeny = %v, want everything denied", deny)
	}
}

// Quarantining twice, or two operators at once, must not fail on the policy
// already being there.
func TestQuarantineIsRepeatable(t *testing.T) {
	s := quarantineStore(suspectPod())
	ctx := context.Background()
	if err := s.Quarantine(ctx, "demo", "compromised", "andy"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.Quarantine(ctx, "demo", "compromised", "sam"); err != nil {
		t.Fatalf("second: %v", err)
	}
}

func TestReleaseRemovesTheLabelAndTheRecord(t *testing.T) {
	s := quarantineStore(suspectPod())
	ctx := context.Background()
	if err := s.Quarantine(ctx, "demo", "compromised", "andy"); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, "demo", "compromised"); err != nil {
		t.Fatalf("Release: %v", err)
	}

	p, _ := s.typed.CoreV1().Pods("demo").Get(ctx, "compromised", metav1.GetOptions{})
	if _, ok := p.Labels[QuarantineLabel]; ok {
		t.Error("the label survived release, so the pod is still contained")
	}
	// Otherwise a pod quarantined again later carries the previous decision's
	// operator and timestamp.
	if p.Annotations[quarantineByAnnotation] != "" {
		t.Errorf("quarantined-by = %q, want it cleared", p.Annotations[quarantineByAnnotation])
	}
}

// The label is the state, so the list is read from the cluster rather than from
// anything Sentinel holds — which is what makes it survive a restart.
func TestListQuarantinedReadsTheCluster(t *testing.T) {
	s := quarantineStore(suspectPod(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy", Namespace: "demo"},
	})
	ctx := context.Background()
	if err := s.Quarantine(ctx, "demo", "compromised", "andy"); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListQuarantined(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d pods, want only the contained one: %+v", len(got), got)
	}
	if got[0].Pod != "compromised" || got[0].By != "andy" || got[0].Node != "w1" {
		t.Errorf("got %+v, want the pod, who asked, and where it runs", got[0])
	}
}

func TestQuarantineNeedsAPod(t *testing.T) {
	s := quarantineStore()
	if err := s.Quarantine(context.Background(), "demo", "", "andy"); err == nil {
		t.Error("an empty pod name was accepted")
	}
}

// The graph went on saying "Blocked by policy" for up to the whole fifteen-minute
// window after a pod was released — and could name no policy for it, because the
// one that dropped the traffic no longer selected the pod. Releasing is the
// moment Sentinel knows those drops have stopped.
func TestReleaseClearsTheDenialsItCaused(t *testing.T) {
	s := quarantineStore(suspectPod())
	now := time.Now()
	s.SeedCiliumTopoForTest([]CiliumTopoEntry{
		{Key: "in", SrcPod: "client", SrcNs: "demo", DstPod: "compromised", DstNs: "demo",
			Verdict: "dropped", Count: 5, LastSeen: now},
		{Key: "out", SrcPod: "compromised", SrcNs: "demo", DstPod: "api", DstNs: "demo",
			Verdict: "dropped", Count: 3, LastSeen: now},
		// Another pod's denial is none of this pod's business.
		{Key: "other", SrcPod: "unrelated", SrcNs: "demo", DstPod: "api", DstNs: "demo",
			Verdict: "dropped", Count: 1, LastSeen: now},
		// And traffic that was allowed still happened.
		{Key: "allowed", SrcPod: "compromised", SrcNs: "demo", DstPod: "dns", DstNs: "kube-system",
			Verdict: "allowed", Count: 9, LastSeen: now},
	})

	if err := s.Release(context.Background(), "demo", "compromised"); err != nil {
		t.Fatalf("Release: %v", err)
	}

	left := map[string]bool{}
	for _, e := range s.ListCiliumTopoEntries() {
		left[e.Key] = true
	}
	for _, gone := range []string{"in", "out"} {
		if left[gone] {
			t.Errorf("denial %q survived release, so the graph still reports the pod as blocked", gone)
		}
	}
	if !left["other"] {
		t.Error("another pod's denial was cleared")
	}
	if !left["allowed"] {
		t.Error("allowed traffic was cleared — only the denials are stale")
	}
}

// Events outlive the pods that raised them, so the button is still on an event
// whose workload was replaced hours ago. "pods not found" alone reads like a
// bug in Sentinel rather than a fact about the cluster.
func TestQuarantiningAGonePodSaysWhy(t *testing.T) {
	s := quarantineStore() // no pods at all

	err := s.Quarantine(context.Background(), "demo", "long-gone", "andy")
	if err == nil {
		t.Fatal("quarantining a pod that does not exist reported success")
	}
	if !strings.Contains(err.Error(), "no longer exists") {
		t.Errorf("error = %q, want it to say the pod is gone", err)
	}
}
