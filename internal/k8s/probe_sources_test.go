package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// podWith builds a single-container pod on node w1 so each case below differs
// only in how the container declares the port the kubelet will reach.
func podWith(c corev1.Container) *corev1.Pod {
	c.Name = "app"
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "demo"},
		Spec:       corev1.PodSpec{NodeName: "w1", Containers: []corev1.Container{c}},
	}
}

func recognises(t *testing.T, c corev1.Container, port string) bool {
	t.Helper()
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(podWith(c)), nil, "")
	return store.IsHealthProbe(context.Background(), "w1", "demo", "workload", port)
}

// Every way a container can declare something the kubelet will connect to. Each
// one produces node-to-pod traffic that is not the workload's own, so each has
// to be recognisable — otherwise it shows on the graph as an unexplained edge
// that "Hide health probes" cannot remove.
func TestEveryKubeletReachablePortIsRecognised(t *testing.T) {
	cases := []struct {
		name string
		c    corev1.Container
		port string
	}{
		{"httpGet liveness", corev1.Container{
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080)}}},
		}, "8080"},

		{"tcpSocket readiness", corev1.Container{
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(5432)}}},
		}, "5432"},

		{"grpc startup", corev1.Container{
			StartupProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				GRPC: &corev1.GRPCAction{Port: 9090}}},
		}, "9090"},

		// The kubelet resolves a named probe port against the container's own
		// ports, so this has to as well.
		{"named port", corev1.Container{
			Ports: []corev1.ContainerPort{{Name: "health", ContainerPort: 8081}},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("health")}}},
		}, "8081"},

		// A named port on a tcpSocket probe takes the same path.
		{"named tcpSocket port", corev1.Container{
			Ports: []corev1.ContainerPort{{Name: "db", ContainerPort: 5433}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("db")}}},
		}, "5433"},

		// Lifecycle hooks are the kubelet connecting to the container too.
		{"postStart httpGet hook", corev1.Container{
			Lifecycle: &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(7000)}}},
		}, "7000"},

		{"preStop httpGet hook", corev1.Container{
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(7001)}}},
		}, "7001"},

		{"preStop hook on a named port", corev1.Container{
			Ports: []corev1.ContainerPort{{Name: "admin", ContainerPort: 7002}},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("admin")}}},
		}, "7002"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !recognises(t, tc.c, tc.port) {
				t.Errorf("port %s was not recognised as kubelet traffic", tc.port)
			}
		})
	}
}

// An exec probe runs a command inside the container. Nothing crosses the
// network, so there is no port and nothing to hide — and claiming one would
// hide real traffic that happens to use that number.
func TestAnExecProbeContributesNoPort(t *testing.T) {
	c := corev1.Container{
		Name: "app",
		LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "true"}}}},
	}
	if probePort(c.LivenessProbe, c) != "" {
		t.Error("an exec probe produced a port")
	}
}

// A sleep hook is not network traffic either, and tcpSocket is in the API but
// the kubelet does not implement it for hooks.
func TestNonHTTPLifecycleHooksContributeNoPort(t *testing.T) {
	c := corev1.Container{Name: "app"}
	sleep := &corev1.LifecycleHandler{Sleep: &corev1.SleepAction{Seconds: 5}}
	if hookPort(sleep, c) != "" {
		t.Error("a sleep hook produced a port")
	}
	exec := &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"true"}}}
	if hookPort(exec, c) != "" {
		t.Error("an exec hook produced a port")
	}
	if hookPort(nil, c) != "" {
		t.Error("an absent hook produced a port")
	}
}

// A named port the container never declares cannot be resolved — the kubelet
// cannot run that probe either. Guessing a number here would hide real traffic.
func TestAnUnresolvableNamedPortIsNotGuessed(t *testing.T) {
	c := corev1.Container{
		Name: "app",
		LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("nowhere")}}},
	}
	if got := probePort(c.LivenessProbe, c); got != "" {
		t.Errorf("got %q, want no port for a name the container does not declare", got)
	}
}

// A container's named port is its own. Resolving against another container's
// declarations would invent a port the kubelet never probes.
func TestANamedPortDoesNotResolveAcrossContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "demo"},
		Spec: corev1.PodSpec{NodeName: "w1", Containers: []corev1.Container{
			{Name: "sidecar", Ports: []corev1.ContainerPort{{Name: "health", ContainerPort: 9999}}},
			{Name: "app", LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("health")}}}},
		}},
	}
	store := NewStore(emptyPolicyClient(), k8sfake.NewSimpleClientset(pod), nil, "")
	if store.IsHealthProbe(context.Background(), "w1", "demo", "workload", "9999") {
		t.Error("a named port was resolved against another container's declarations")
	}
}
