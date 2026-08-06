package k8s

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func always() *corev1.ContainerRestartPolicy {
	p := corev1.ContainerRestartPolicyAlways
	return &p
}

// istioInjected is a pod as Istio injects it on Kubernetes 1.29+: the proxy is a
// native sidecar, an init container with restartPolicy Always, and it is the
// only container carrying a probe — the application declares none.
func istioInjected() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "helloworld-v1", Namespace: "test"},
		Spec: corev1.PodSpec{
			NodeName: "w1",
			InitContainers: []corev1.Container{{
				Name:          "istio-proxy",
				RestartPolicy: always(),
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/healthz/ready",
						Port: intstr.FromInt32(15021),
					},
				}},
			}},
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
}

// The kubelet probing an Istio sidecar on 15021 was indistinguishable from
// workload traffic, because the probe is declared on the sidecar and the sidecar
// is an init container. "Hide health probes" could not hide it, and the graph
// showed a node connecting to the pod for no visible reason.
func TestANativeSidecarsProbeIsRecognised(t *testing.T) {
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(istioInjected()), nil, "")

	if !store.IsHealthProbe(context.Background(), "w1", "test", "helloworld-v1", "15021") {
		t.Error("the sidecar's readiness probe on 15021 was not recognised as a health probe")
	}
}

// The same omission left the sidecar out of the container list, so a network
// event for this pod named only half of what runs in it — and every container
// in a pod shares the network namespace, which is why they are all listed.
func TestANativeSidecarAppearsInTheContainerList(t *testing.T) {
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(istioInjected()), nil, "")

	got := store.PodContainer(context.Background(), "test", "helloworld-v1")
	if !strings.Contains(got, "istio-proxy") {
		t.Errorf("containers = %q, want the injected sidecar included", got)
	}
	if !strings.Contains(got, "app") {
		t.Errorf("containers = %q, want the application container included", got)
	}
}

// An ordinary init container has finished long before any flow is seen, and
// Kubernetes does not allow probes on one. Including it would name a container
// that is not running.
func TestAnOrdinaryInitContainerIsNotListed(t *testing.T) {
	pod := istioInjected()
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: "istio-init"})
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(pod), nil, "")

	if got := store.PodContainer(context.Background(), "test", "helloworld-v1"); strings.Contains(got, "istio-init") {
		t.Errorf("containers = %q, want the one-shot init container left out", got)
	}
}

// The node still has to match: the same port reached from anywhere else is
// ordinary traffic, and the fix must not weaken that.
func TestASidecarProbePortFromAnotherNodeIsNotAProbe(t *testing.T) {
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(istioInjected()), nil, "")

	if store.IsHealthProbe(context.Background(), "w2", "test", "helloworld-v1", "15021") {
		t.Error("traffic to the probe port from a different node was treated as a probe")
	}
}
