package k8s

import (
	"strings"
	"testing"
	"time"

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
	start := time.Now()
	l.exited(entry, conmon, start)
	// Not at once: what it started may not have run anything yet.
	if got := l.place(proc("entry", "", "/bin/sh", ""), nil); got != cidA {
		t.Errorf("a moment after it exited: %q, want %q", got, cidA)
	}
	// The next exit past the wait takes it out.
	l.exited(proc("other", "", "/bin/true", ""), nil, start.Add(orphanFor))
	if got := l.place(proc("entry", "", "/bin/sh", ""), nil); got != "" {
		t.Errorf("still placed in %q", got)
	}
}

// "( (work) & )": the shell forks, the fork forks into the background and
// exits, and only then does the second fork run anything. Its parent is gone
// and was the subject of no event but its own exit, which is where the way up
// the tree is learned.
func TestWhatAnExitedForkLeftRunningIsPlaced(t *testing.T) {
	l := newContainerLineage()
	shell := proc("shell", "conmon", "/bin/sh", "-c loop")
	l.place(shell, conmon)
	first := proc("first", "shell", "/bin/sh", "-c loop")
	second := proc("second", "first", "/bin/sh", "-c loop")
	l.exited(first, shell, time.Now())
	if got := l.place(proc("work", "second", "/bin/sh", "-c loop"), second); got != cidA {
		t.Errorf("what the background fork ran = %q, want %q", got, cidA)
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

// What "create" starts directly is a hook on the node; what a monitor or
// "exec" starts is in the container.
func TestStartsInContainer(t *testing.T) {
	cases := []struct{ binary, args, want string }{
		{"/usr/bin/conmon", "-b /run/x -c " + cidA + " -n k8s_app", cidA},
		{"/usr/libexec/crio/crun", "--root /run/crun exec --process /tmp/p " + cidA, cidA},
		{"/dev/fd/3", "--root /run/crun exec --process /tmp/p " + cidA, cidA},
		{"/usr/sbin/runc", "--root /run/runc exec --detach " + cidA, cidA},
		{"/usr/libexec/crio/crun", "--root /run/crun create --bundle /run/b " + cidA, ""},
		{"/usr/sbin/runc", "--root /run/runc run " + cidA, ""},
		{"/bin/sh", "-c exec " + cidA, ""},
	}
	for _, c := range cases {
		if got := startsInContainer(c.binary, c.args); got != c.want {
			t.Errorf("startsInContainer(%q, %q) = %q, want %q", c.binary, c.args, got, c.want)
		}
	}
}

func TestRuntimeIsToldByNameNotSubstring(t *testing.T) {
	for _, b := range []string{"/usr/bin/truncate", "/usr/bin/scrunch", "/usr/local/bin/containerd-shim-runc-v2", "/bin/sh"} {
		if isContainerRuntime(b) {
			t.Errorf("%s was taken for a container runtime", b)
		}
	}
	for _, b := range []string{"/usr/sbin/runc", "/usr/libexec/crio/crun", "/usr/bin/conmon", "/usr/bin/conmonrs", "/dev/fd/3", "/proc/self/fd/6", "/memfd:runc_cloned:/proc/self/exe", "/proc/self/exe"} {
		if !isContainerRuntime(b) {
			t.Errorf("%s was not taken for a container runtime", b)
		}
	}
}

func TestStrayContainersAndSeedRequests(t *testing.T) {
	l := newContainerLineage()
	if l.isNoPods(cidA) {
		t.Fatal("stray before being found so")
	}
	l.noPods(cidA)
	if !l.isNoPods(cidA) || l.isNoPods(cidB) {
		t.Fatal("stray containers misremembered")
	}
	agent := podEndpoint{Name: "tetragon-x", IP: "10.0.0.1", Node: "n1"}
	if l.takeSeed(agent) {
		t.Fatal("a seed nobody asked for")
	}
	l.askSeed(agent)
	if !l.takeSeed(agent) || l.takeSeed(agent) {
		t.Fatal("a seed request is taken once")
	}
}

// A shell forks for "$(...)" and for a subshell without executing anything, so
// those forks are the subject of no event. What they start is still in the
// container, and was reported with no pod at all: on CRI-O every command in a
// substituted pipeline, Sentinel's own script in the agent among them.
func TestAProcessStartedThroughForksIsPlaced(t *testing.T) {
	l := newContainerLineage()
	monitor := proc("conmon", "", "/usr/bin/conmon", "-b /run/x -c "+cidA+" -u "+cidA)
	shell := proc("shell", "conmon", "/bin/sh", "-c loop")
	if got := l.place(shell, monitor); got != cidA {
		t.Fatalf("the container's shell = %q", got)
	}
	// x=$(cat f | wc -c): the shell forks, and the fork starts both.
	fork := proc("fork", "shell", "/bin/sh", "-c loop")
	if got := l.place(proc("cat", "fork", "/bin/sh", "-c loop"), fork); got != cidA {
		t.Errorf("a command one fork down = %q, want %q", got, cidA)
	}
	// $( (hostname | tr a-z A-Z) | md5sum ): a fork of a fork. The inner one is
	// reached once anything names the outer one's parent, in either order.
	outer := proc("outer", "shell", "/bin/sh", "-c loop")
	inner := proc("inner", "outer", "/bin/sh", "-c loop")
	hostname := proc("hostname", "inner", "/bin/sh", "-c loop")
	if got := l.place(hostname, inner); got != "" {
		t.Fatalf("two forks down with nothing yet said of the outer = %q", got)
	}
	if got := l.place(proc("md5sum", "outer", "/bin/sh", "-c loop"), outer); got != cidA {
		t.Errorf("a sibling of the inner fork = %q, want %q", got, cidA)
	}
	if got := l.place(proc("tr", "inner", "/bin/sh", "-c loop"), inner); got != cidA {
		t.Errorf("two forks down = %q, want %q", got, cidA)
	}
	if got := l.place(hostname, inner); got != cidA {
		t.Errorf("the one that came too early, asked again = %q, want %q", got, cidA)
	}
	// What was never under a container stays unplaced, loops included.
	a, b := proc("a", "b", "/bin/sh", ""), proc("b", "a", "/bin/sh", "")
	if got := l.place(a, b); got != "" {
		t.Errorf("parents that loop = %q", got)
	}
}

// The runtime reading its own files on the way into a container is not what
// the workload did. A policy that killed it for that is why the container
// would not start, and is told.
func TestARuntimeThePolicyStoppedIsNotLeftOut(t *testing.T) {
	for _, c := range []struct {
		binary, action string
		own            bool
	}{
		{"/usr/local/sbin/runc", "monitor", true},
		{"/usr/local/sbin/runc", "kill", false},
		{"/usr/bin/crun", "deny", false},
		{"/bin/cat", "monitor", false},
		{"/bin/cat", "kill", false},
	} {
		if got := runtimesOwn(TetragonEvent{Binary: c.binary, Action: c.action}); got != c.own {
			t.Errorf("%s, %s: own = %v, want %v", c.binary, c.action, got, c.own)
		}
	}
}
