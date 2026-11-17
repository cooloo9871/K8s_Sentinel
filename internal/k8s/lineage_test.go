package k8s

import (
	"strings"
	"testing"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	cidA = "3c29aeb330bdd7d81ca38dc0fb33b47dc9a3e4f55e3ca29cd6555de8b7ec1ead"
	cidB = "0144c994d38ae60b2888a5a0920044fd454ee43bdc5960b750e32474d27f6d36"
)

func proc(execID, parentExecID, binary, args string) *tetragon.Process {
	return &tetragon.Process{ExecId: execID, ParentExecId: parentExecID, Binary: binary, Arguments: args}
}

// What CRI-O with crun shows, taken from a node: none of these events carries
// a pod.
var (
	conmon     = proc("conmon", "crio", "/usr/libexec/crio/conmon", "-b /run/containers/storage/overlay-containers/"+cidA+"/userdata -c "+cidA+" --exit-dir /var/run/crio/exits")
	crunCreate = proc("create", "conmon", "/usr/libexec/crio/crun", "--systemd-cgroup --root=/run/crun create --bundle /run/containers/storage/overlay-containers/"+cidA+"/userdata "+cidA)
	entry      = proc("entry", "conmon", "/bin/sh", `-c "ls /; sleep 3600"`)
	child      = proc("child", "entry", "/bin/ls", "/")
	crunExec   = proc("crunexec", "crio", "/usr/libexec/crio/crun", "--root /run/crun --systemd-cgroup exec --process /tmp/exec-process-1 "+cidA)
	sealed     = proc("sealed", "crunexec", "/dev/fd/3", "--root /run/crun --systemd-cgroup exec --process /tmp/exec-process-1 "+cidA)
	execd      = proc("execd", "sealed", "/bin/cat", "/etc/hostname")
)

func TestAProcessIsPlacedByWhatStartedIt(t *testing.T) {
	l := newContainerLineage()

	if got := l.place(entry, conmon); got != cidA {
		t.Errorf("a container's first process, a child of its monitor: got %q", got)
	}
	// The event for a grandchild carries only its parent, which names nothing.
	if got := l.place(child, entry); got != cidA {
		t.Errorf("what that process started: got %q", got)
	}
	if got := l.place(execd, sealed); got != cidA {
		t.Errorf("a process put into the container later, by a runtime running from a sealed copy: got %q", got)
	}
	// A later event about the same process, a kprobe, needs no parent at all.
	if got := l.place(proc("child", "", "/bin/ls", "/"), nil); got != cidA {
		t.Errorf("a process seen before: got %q", got)
	}
}

func TestTheRuntimeItselfIsNotInTheContainer(t *testing.T) {
	l := newContainerLineage()
	for _, c := range []struct{ p, parent *tetragon.Process }{
		{crunCreate, conmon},
		{sealed, crunExec},
		{conmon, proc("crio", "", "/usr/bin/crio", "")},
		{crunExec, proc("crio", "", "/usr/bin/crio", "")},
	} {
		if got := l.place(c.p, c.parent); got != "" {
			t.Errorf("%s %s was placed in %q", c.p.Binary, strings.Fields(c.p.Arguments)[0], got)
		}
	}
}

// What containerd with runc shows for "kubectl exec": the shim carries the ID
// of the sandbox, which no container of the pod has, and must not be taken
// for the container's.
func TestContainerdsShimPlacesNothing(t *testing.T) {
	l := newContainerLineage()
	shim := proc("shim", "systemd", "/usr/local/bin/containerd-shim-runc-v2", "-namespace k8s.io -id "+cidB+" -address /run/containerd/containerd.sock")
	runcExec := proc("runcexec", "shim", "/usr/local/sbin/runc", "--root /run/containerd/runc/k8s.io exec --process /tmp/runc-process1 --detach "+cidA)
	runcInit := proc("runcinit", "runcexec", "/proc/self/fd/6", "init")

	if got := l.place(runcExec, shim); got != "" {
		t.Errorf("runc, started by the shim, was placed in %q", got)
	}
	if got := l.place(runcInit, runcExec); got != "" {
		t.Errorf("runc init was placed in %q", got)
	}
	// The process runc init becomes is started by a runtime that names the
	// container.
	if got := l.place(proc("date", "runcexec", "/bin/date", ""), runcExec); got != cidA {
		t.Errorf("the process that was exec'd into the container: got %q", got)
	}
}

func TestAProcessOfTheNodeIsNotPlaced(t *testing.T) {
	l := newContainerLineage()
	// A container ID on the command line of something that is not a runtime.
	script := proc("script", "sshd", "/bin/bash", "cleanup.sh "+cidA)
	if got := l.place(proc("ls", "script", "/bin/ls", "/"), script); got != "" {
		t.Errorf("placed in %q", got)
	}
	if got := l.place(proc("kubelet", "systemd", "/usr/bin/kubelet", ""), proc("systemd", "", "/usr/lib/systemd/systemd", "")); got != "" {
		t.Errorf("placed in %q", got)
	}
}

func TestAnExitedProcessIsForgotten(t *testing.T) {
	l := newContainerLineage()
	l.place(entry, conmon)
	l.forget("entry")
	if got := l.place(proc("entry", "", "/bin/sh", ""), nil); got != "" {
		t.Errorf("still placed in %q", got)
	}
}

// The cache of an agent that started after the containers did: every process
// read from /proc, parents included, in no particular order.
func TestSeedingPlacesProcessesThatWereAlreadyRunning(t *testing.T) {
	l := newContainerLineage()
	monitorB := proc("conmonB", "crio", "/usr/libexec/crio/conmon", "-c "+cidB+" -u "+cidB)
	nginx := proc("nginx", "conmonB", "/usr/sbin/nginx", "-g daemon off;")
	worker := proc("worker", "nginx", "/usr/sbin/nginx", "")
	known := proc("known", "x", "/bin/app", "")
	known.Pod = &tetragon.Pod{Name: "p", Namespace: "n"}

	placed := l.seed([]*tetragon.Process{child, worker, entry, conmon, crunCreate, nginx, monitorB, known,
		proc("kubelet", "systemd", "/usr/bin/kubelet", "")})

	want := map[*tetragon.Process]string{child: cidA, entry: cidA, nginx: cidB, worker: cidB}
	if len(placed) != len(want) {
		t.Errorf("placed %d processes, want %d", len(placed), len(want))
	}
	for p, cid := range want {
		if placed[p] != cid {
			t.Errorf("%s: got %q, want %q", p.ExecId, placed[p], cid)
		}
	}
	// And what they start afterwards follows.
	if got := l.place(proc("new", "worker", "/bin/date", ""), nil); got != cidB {
		t.Errorf("a child of a seeded process: got %q", got)
	}
}

func TestTheTableIsBounded(t *testing.T) {
	l := newContainerLineage()
	for i := 0; i < lineageMax+10; i++ {
		l.put(strings.Repeat("x", 1)+string(rune(i)), cidA)
	}
	if len(l.ids) > lineageMax {
		t.Errorf("holds %d entries, over the limit of %d", len(l.ids), lineageMax)
	}
}

func TestRuntimeContainerID(t *testing.T) {
	for _, c := range []struct{ binary, args, want string }{
		{"/usr/bin/runc", "--root /run/containerd/runc/k8s.io exec --process /tmp/x " + cidA, cidA},
		{"/memfd:runc_cloned:/proc/self/exe", "init " + cidA, cidA},
		{"/usr/libexec/crio/crun", "exec " + cidA, cidA},
		{"/usr/bin/conmon", "-c " + cidA, cidA},
		{"/usr/bin/conmonrs", "-c " + cidA, cidA},
		{"/dev/fd/3", "exec " + cidA, cidA},
		{"/usr/bin/crun", "--version", ""},
		{"/usr/local/bin/containerd-shim-runc-v2", "-namespace k8s.io -id " + cidA, ""},
		{"/bin/bash", "script.sh " + cidA, ""},
		{"/usr/bin/kubectl", "logs " + cidA, ""},
	} {
		if got := runtimeContainerID(c.binary, c.args); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.binary, c.args, got, c.want)
		}
	}
}
