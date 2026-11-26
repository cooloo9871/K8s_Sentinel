package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func lockedPod(name, image, cid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", Labels: map[string]string{"app": "web"}},
		Spec:       corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "web", ImageID: image, ContainerID: "containerd://" + cid,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
}

func webDeployment(mutate func(*corev1.PodSpec)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web"}}}},
		},
	}
	if mutate != nil {
		mutate(&d.Spec.Template.Spec)
	}
	return d
}

// imageLockStore answers the node read with the given files per container ID.
func imageLockStore(t *testing.T, files map[string][]string, objs ...runtime.Object) *Store {
	t.Helper()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		tracingPolicyGVR:           "TracingPolicyList",
		tracingPolicyNamespacedGVR: "TracingPolicyNamespacedList",
	})
	prev := imageFilesOn
	imageFilesOn = func(_ context.Context, _ *Store, _ string, ids []string) ([]byte, error) {
		var b strings.Builder
		for _, id := range ids {
			if _, ok := files[id]; !ok {
				continue
			}
			b.WriteString(id + "\t\n")
			for _, f := range files[id] {
				b.WriteString(id + "\t" + f + "\n")
			}
		}
		return []byte(b.String()), nil
	}
	t.Cleanup(func() { imageFilesOn = prev })
	return NewStore(dyn, k8sfake.NewSimpleClientset(objs...), nil, "")
}

func lockSelectors(t *testing.T, obj map[string]any) []any {
	t.Helper()
	probes, _, _ := unstructured.NestedSlice(obj, "spec", "kprobes")
	if len(probes) != 1 {
		t.Fatalf("kprobes = %d, want 1", len(probes))
	}
	sels, _ := probes[0].(map[string]any)["selectors"].([]any)
	return sels
}

func lockPaths(t *testing.T, obj map[string]any) []string {
	t.Helper()
	sels := lockSelectors(t, obj)
	args, _ := sels[len(sels)-1].(map[string]any)["matchArgs"].([]any)
	vals, _ := args[0].(map[string]any)["values"].([]any)
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i], _ = v.(string)
	}
	return out
}

func TestImageFilesOutputIsReadPerContainer(t *testing.T) {
	out := "aa\t\naa\t/usr/bin/id\naa\t/bin/sh\nbb\t\n" +
		"aa\tnot-a-path\naa\t/x\t/tmp/evil\nstray line\n"
	got := parseImageFiles([]byte(out))
	if strings.Join(got["aa"], ",") != "/usr/bin/id,/bin/sh" {
		t.Errorf("aa = %v: a line that is not one ID and one path adds nothing", got["aa"])
	}
	if files, found := got["bb"]; !found || len(files) != 0 {
		t.Errorf("bb = %v, %v: a container that was found and listed nothing is known to be empty", files, found)
	}
}

func TestAnImageLockListsTheImageAndTheContainersOwnProcesses(t *testing.T) {
	s := imageLockStore(t, map[string][]string{"c1": {"/usr/sbin/nginx", "/bin/sh"}},
		webDeployment(nil), lockedPod("web-1", "sha256:one", "c1"))

	blocksOutside, err := s.CreateImageLock(context.Background(), "shop", Workload{"Deployment", "web"}, "Protect", "andy")
	if err != nil {
		t.Fatal(err)
	}
	if !blocksOutside {
		t.Error("a workload the kubelet runs nothing in has commands from outside stopped")
	}
	rec, err := s.Get(context.Background(), "image-lock-web", "shop")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Mode != "Protect" || rec.ImageLock != "Deployment/web" || rec.CreatedBy != "andy" {
		t.Errorf("record = %+v", rec)
	}
	obj, _ := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("shop").Get(context.Background(), "image-lock-web", metav1.GetOptions{})
	if got := strings.Join(lockPaths(t, obj.Object), ","); got != "/bin/sh,/usr/sbin/nginx" {
		t.Errorf("paths = %s", got)
	}
	if n := len(lockSelectors(t, obj.Object)); n != 2 {
		t.Errorf("selectors = %d, want the process tree and the list", n)
	}
	names, _, _ := unstructured.NestedSlice(obj.Object, "spec", "containerSelector", "matchExpressions")
	if vals, _ := names[0].(map[string]any)["values"].([]any); len(vals) != 1 || vals[0] != "web" {
		t.Errorf("containers = %v, want only the ones that were read", vals)
	}
}

// A probe is started from outside the container like a kubectl exec is. Killing
// what is not started by the container would fail every probe.
func TestAWorkloadTheKubeletRunsCommandsInKeepsThem(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.PodSpec){
		"exec probe": func(p *corev1.PodSpec) {
			p.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{}}}
		},
		"preStop": func(p *corev1.PodSpec) {
			p.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{}}}
		},
		"shared process namespace": func(p *corev1.PodSpec) { yes := true; p.ShareProcessNamespace = &yes },
		"host PID":                 func(p *corev1.PodSpec) { p.HostPID = true },
	} {
		s := imageLockStore(t, map[string][]string{"c1": {"/bin/sh"}},
			webDeployment(mutate), lockedPod("web-1", "sha256:one", "c1"))
		blocksOutside, err := s.CreateImageLock(context.Background(), "shop", Workload{"Deployment", "web"}, "Protect", "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		obj, _ := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("shop").Get(context.Background(), "image-lock-web", metav1.GetOptions{})
		if n := len(lockSelectors(t, obj.Object)); blocksOutside || n != 1 {
			t.Errorf("%s: blocksOutside = %v, selectors = %d: only the list applies", name, blocksOutside, n)
		}
	}
}

// An empty list would stop everything the workload runs.
func TestNoPolicyIsMadeFromAnEmptyOrMissingList(t *testing.T) {
	for name, files := range map[string]map[string][]string{
		"container not found": {},
		"nothing listed":      {"c1": nil},
	} {
		s := imageLockStore(t, files, webDeployment(nil), lockedPod("web-1", "sha256:one", "c1"))
		if _, err := s.CreateImageLock(context.Background(), "shop", Workload{"Deployment", "web"}, "Protect", ""); err == nil {
			t.Errorf("%s: a policy was made", name)
		}
	}
	s := imageLockStore(t, nil, webDeployment(nil))
	if _, err := s.CreateImageLock(context.Background(), "shop", Workload{"Deployment", "web"}, "Protect", ""); !errors.Is(err, ErrNoRunningPod) {
		t.Errorf("no pod: err = %v", err)
	}
	if _, err := s.CreateImageLock(context.Background(), "shop", Workload{"Deployment", "gone"}, "Protect", ""); !errors.Is(err, ErrWorkloadNotFound) {
		t.Errorf("no workload: err = %v", err)
	}
}

func TestARolloutAddsTheNewImageAndKeepsTheMode(t *testing.T) {
	files := map[string][]string{"c1": {"/bin/sh", "/old"}}
	s := imageLockStore(t, files, webDeployment(nil), lockedPod("web-1", "sha256:one", "c1"))
	ctx := context.Background()
	if _, err := s.CreateImageLock(ctx, "shop", Workload{"Deployment", "web"}, "Protect", "andy"); err != nil {
		t.Fatal(err)
	}
	get := func() *unstructured.Unstructured {
		o, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("shop").Get(ctx, "image-lock-web", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}

	// Nothing changed: nothing is written.
	before := get().GetAnnotations()[annotationImageLockBuilt]
	s.syncImageLocks(ctx)
	if get().GetAnnotations()[annotationImageLockBuilt] != before {
		t.Error("an unchanged workload was rebuilt")
	}

	// A pod of the new image starts beside the old one.
	files["c2"] = []string{"/bin/sh", "/new"}
	if _, err := s.typed.CoreV1().Pods("shop").Create(ctx, lockedPod("web-2", "sha256:two", "c2"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.syncImageLocks(ctx)
	o := get()
	if got := strings.Join(lockPaths(t, o.Object), ","); got != "/bin/sh,/new,/old" {
		t.Errorf("during the rollout paths = %s, want both images", got)
	}
	if detectMode(o.Object) != "Protect" || o.GetAnnotations()[annotationCreatedBy] != "andy" {
		t.Errorf("mode = %s, created by %q: a rebuild keeps both", detectMode(o.Object), o.GetAnnotations()[annotationCreatedBy])
	}

	// The old pod goes.
	if err := s.typed.CoreV1().Pods("shop").Delete(ctx, "web-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	s.syncImageLocks(ctx)
	if got := strings.Join(lockPaths(t, get().Object), ","); got != "/bin/sh,/new" {
		t.Errorf("after the rollout paths = %s", got)
	}

	// Set to Monitoring, then the image changes again: it stays in Monitoring.
	if err := s.SetPolicyMode(ctx, "image-lock-web", "shop", "Monitoring"); err != nil {
		t.Fatal(err)
	}
	files["c3"] = []string{"/bin/sh"}
	_ = s.typed.CoreV1().Pods("shop").Delete(ctx, "web-2", metav1.DeleteOptions{})
	_, _ = s.typed.CoreV1().Pods("shop").Create(ctx, lockedPod("web-3", "sha256:three", "c3"), metav1.CreateOptions{})
	s.syncImageLocks(ctx)
	if o := get(); detectMode(o.Object) != "Monitoring" || strings.Join(lockPaths(t, o.Object), ",") != "/bin/sh" {
		t.Errorf("mode = %s, paths = %v", detectMode(o.Object), lockPaths(t, o.Object))
	}
}
