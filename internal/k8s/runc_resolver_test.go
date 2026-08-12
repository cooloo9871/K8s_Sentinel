package k8s

import (
	"context"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// A container ID that resolves to nothing is ordinary — a container that has
// already exited, or runc acting on a sandbox. Without caching that outcome the
// next event carrying the same ID listed every pod again, and each of those is a
// quorum read against etcd.
func TestAnUnresolvableContainerIDIsListedOnce(t *testing.T) {
	typed := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "known", Namespace: "demo"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", ContainerID: "containerd://aaa"},
		}},
	})
	var lists atomic.Int32
	typed.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		return false, nil, nil
	})
	s := NewStore(nil, typed, nil, "")

	for i := 0; i < 5; i++ {
		if pod, _, _ := s.containers.resolve(context.Background(), s, "does-not-exist"); pod != "" {
			t.Fatalf("resolved a container that is not running: %q", pod)
		}
	}

	if n := lists.Load(); n != 1 {
		t.Errorf("listed pods %d times for one unknown ID, want 1", n)
	}
}

// The hit path still works, and still costs one list.
func TestAKnownContainerIDResolves(t *testing.T) {
	typed := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "known", Namespace: "demo"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", ContainerID: "containerd://aaa"},
		}},
	})
	s := NewStore(nil, typed, nil, "")
	pod, ns, ctr := s.containers.resolve(context.Background(), s, "aaa")
	if pod != "known" || ns != "demo" || ctr != "app" {
		t.Errorf("got %s/%s/%s, want demo/known/app", ns, pod, ctr)
	}
}
