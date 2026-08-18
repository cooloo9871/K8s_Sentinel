package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func previewPod(ns, name string, lbl map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbl}}
}

// The preview answers "which pods would this selector govern" before Apply:
// scoped to a namespace when one is given, cluster-wide when not, and empty
// selectors match everything, exactly as they do in a policy.
func TestSelectPods(t *testing.T) {
	typed := k8sfake.NewSimpleClientset(
		previewPod("demo", "web-1", map[string]string{"app": "web"}),
		previewPod("demo", "web-2", map[string]string{"app": "web"}),
		previewPod("demo", "db-1", map[string]string{"app": "db"}),
		previewPod("other", "web-9", map[string]string{"app": "web"}),
	)
	s := NewStore(nil, typed, nil, "")
	ctx := context.Background()

	total, pods, err := s.SelectPods(ctx, "demo", map[string]string{"app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(pods) != 2 || pods[0].Name != "web-1" {
		t.Errorf("namespaced: total=%d pods=%v", total, pods)
	}

	total, _, err = s.SelectPods(ctx, "", map[string]string{"app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("cluster-wide: total=%d, want 3", total)
	}

	// An empty selector selects everything, which is what makes it the mistake
	// worth previewing.
	total, _, err = s.SelectPods(ctx, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("empty selector: total=%d, want 4", total)
	}

	total, _, err = s.SelectPods(ctx, "demo", map[string]string{"app": "nothing"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Errorf("no match: total=%d, want 0", total)
	}
}
