package k8s

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

	total, pods, _, err := s.SelectPods(ctx, "demo", map[string]string{"app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(pods) != 2 || pods[0].Name != "web-1" {
		t.Errorf("namespaced: total=%d pods=%v", total, pods)
	}

	total, _, _, err = s.SelectPods(ctx, "", map[string]string{"app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("cluster-wide: total=%d, want 3", total)
	}

	// An empty selector selects everything, which is what makes it the mistake
	// worth previewing.
	total, _, _, err = s.SelectPods(ctx, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("empty selector: total=%d, want 4", total)
	}

	total, _, _, err = s.SelectPods(ctx, "demo", map[string]string{"app": "nothing"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Errorf("no match: total=%d, want 0", total)
	}
}

// Typed-wrong input is the caller's error, not the cluster's, and a value
// containing a comma must not splice extra conditions into the selector.
func TestSelectPodsRefusesAnInvalidSelector(t *testing.T) {
	s := NewStore(nil, k8sfake.NewSimpleClientset(), nil, "")
	for _, labels := range []map[string]string{
		{"app": "web,run=db"},
		{"bad key!": "x"},
	} {
		_, _, _, err := s.SelectPods(context.Background(), "", labels)
		if !errors.Is(err, ErrInvalidSelector) {
			t.Errorf("labels %v: err = %v, want ErrInvalidSelector", labels, err)
		}
	}
}

// The form offers these to choose from, so they are those of every pod matched,
// past the names the preview is cut to, each once.
func TestSelectPodsNamesTheirContainers(t *testing.T) {
	pod := func(name string, init []string, containers ...string) *corev1.Pod {
		p := previewPod("demo", name, map[string]string{"app": "web"})
		for _, c := range init {
			p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: c})
		}
		for _, c := range containers {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
		}
		return p
	}
	objs := []runtime.Object{pod("web-00", []string{"setup"}, "nginx", "proxy")}
	for i := 1; i <= previewCap; i++ {
		objs = append(objs, pod(fmt.Sprintf("web-%02d", i), nil, "nginx"))
	}
	objs = append(objs, pod("web-99", nil, "nginx", "late"), previewPod("demo", "db", map[string]string{"app": "db"}))
	s := NewStore(nil, k8sfake.NewSimpleClientset(objs...), nil, "")
	_, _, got, err := s.SelectPods(context.Background(), "demo", map[string]string{"app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"late", "nginx", "proxy", "setup"}; !reflect.DeepEqual(got, want) {
		t.Errorf("containers = %v, want %v", got, want)
	}
}
