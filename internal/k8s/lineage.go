package k8s

import (
	"path"
	"strings"
	"sync"
	"time"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
)

// containerLineage remembers which container a process runs in, for the nodes
// where Tetragon cannot say.
//
// Tetragon names the pod of a process from the name of its cgroup. That works
// where the processes of a container sit directly in a cgroup named after it
// (containerd with runc). Where the runtime puts them one level further down,
// in a cgroup called "container" (CRI-O with crun), the name says nothing, and
// every event arrives without a pod. The other way Tetragon has of finding the
// pod, asking the runtime, places some processes and stops namespaced policies
// from being enforced, so it is not used.
//
// What every runtime does leave in plain sight is the container ID on the
// command line of whatever started the process: the monitor a container's
// first process is a child of, or the runtime that put a later one into it. A
// process started by one of those is in that container, and so is everything
// that process starts. This follows that, one exec at a time.
type containerLineage struct {
	mu  sync.Mutex
	ids map[string]string // exec ID → container ID
	// exec ID → parent's exec ID, for processes nothing has placed yet. A
	// process that forks without executing anything (a subshell, the shell
	// behind "$(...)") is the subject of no event, only the parent in its
	// children's, so the way up the tree through it is kept from those.
	parents map[string]string
	// Processes that have exited, oldest first, and when. They are forgotten
	// a while after, not at once: see exited.
	gone []goneProcess
	// Containers that turned out to belong to no pod, and when that was found.
	stray map[string]time.Time
	// Agents whose process cache should be read again.
	reseed map[podEndpoint]bool
}

// lineageMax bounds the table. Entries leave when their process exits; this is
// for the exits that were never heard.
const lineageMax = 200_000

func newContainerLineage() *containerLineage {
	return &containerLineage{
		ids:     make(map[string]string),
		parents: make(map[string]string),
		stray:   make(map[string]time.Time),
		reseed:  make(map[podEndpoint]bool),
	}
}

func (l *containerLineage) get(execID string) string {
	if execID == "" {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ids[execID]
}

func (l *containerLineage) put(execID, containerID string) {
	if execID == "" || containerID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ids) >= lineageMax {
		// Any tenth of them: a process whose entry is lost is one whose
		// children go unplaced, not one that is placed wrongly.
		n := lineageMax / 10
		for id := range l.ids {
			delete(l.ids, id)
			if n--; n == 0 {
				break
			}
		}
	}
	l.ids[execID] = containerID
}

type goneProcess struct {
	execID string
	at     time.Time
}

// orphanFor is how long an exited process stays on the way up the tree. What
// it started may outlive it without having executed anything yet: a shell that
// forks into the background and exits, "( (work) & )". The first thing that
// fork runs is then the child of a process whose own parent is gone, and for
// this long it is still found.
const orphanFor = time.Minute

// exited takes a process that has ended out of the table, a while from now.
// Its exit is also the one event a fork that executed nothing is the subject
// of, and so the one place its own parent is named.
func (l *containerLineage) exited(proc, parent *tetragon.Process, now time.Time) {
	if proc.GetExecId() == "" {
		return
	}
	parentID := proc.GetParentExecId()
	if parentID == "" {
		parentID = parent.GetExecId()
	}
	l.link(proc.GetExecId(), parentID)
	l.climb(proc.GetExecId())
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gone = append(l.gone, goneProcess{proc.GetExecId(), now})
	n := 0
	for n < len(l.gone) && now.Sub(l.gone[n].at) >= orphanFor {
		delete(l.ids, l.gone[n].execID)
		delete(l.parents, l.gone[n].execID)
		n++
	}
	l.gone = l.gone[n:]
}

// link records that a process was started by another.
func (l *containerLineage) link(execID, parentExecID string) {
	if execID == "" || parentExecID == "" || execID == parentExecID {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.parents) >= lineageMax {
		n := lineageMax / 10
		for id := range l.parents {
			delete(l.parents, id)
			if n--; n == 0 {
				break
			}
		}
	}
	l.parents[execID] = parentExecID
}

// lineageDepth bounds the climb up the tree, for parents that loop.
const lineageDepth = 32

// climb follows the recorded parents up from a process to the first one whose
// container is known, and marks everything it passed as in that container.
func (l *containerLineage) climb(execID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var passed []string
	for cur, depth := execID, 0; cur != "" && depth < lineageDepth; depth++ {
		if id := l.ids[cur]; id != "" {
			for _, p := range passed {
				l.ids[p] = id
				delete(l.parents, p)
			}
			return id
		}
		passed = append(passed, cur)
		cur = l.parents[cur]
	}
	return ""
}

// strayFor is how long a container found in no pod is taken to be in none.
const strayFor = 2 * time.Minute

// noPods records that a container was looked for in every pod and not found.
func (l *containerLineage) noPods(containerID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for id, at := range l.stray {
		if now.Sub(at) >= strayFor {
			delete(l.stray, id)
		}
	}
	l.stray[containerID] = now
}

func (l *containerLineage) isNoPods(containerID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	at, ok := l.stray[containerID]
	return ok && time.Since(at) < strayFor
}

// askSeed asks for an agent's process cache to be read again, and takeSeed
// reports, once, whether that was asked.
func (l *containerLineage) askSeed(agent podEndpoint) {
	l.mu.Lock()
	l.reseed[agent] = true
	l.mu.Unlock()
}

func (l *containerLineage) takeSeed(agent podEndpoint) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	asked := l.reseed[agent]
	delete(l.reseed, agent)
	return asked
}

// place returns the container proc runs in, or "" when nothing says. parent is
// the parent as the event carries it, and may be nil.
func (l *containerLineage) place(proc, parent *tetragon.Process) string {
	if proc == nil {
		return ""
	}
	if id := l.get(proc.GetExecId()); id != "" {
		return id
	}
	// A process is in the container of whatever started it, however many
	// forks up that is. The event names the parent and the parent's own
	// parent; the rest of the way is what earlier events said.
	l.link(proc.GetExecId(), proc.GetParentExecId())
	l.link(parent.GetExecId(), parent.GetParentExecId())
	id := l.climb(proc.GetParentExecId())
	// The runtime's own steps, "runc init" or a monitor starting "crun
	// create", are on the node and not what the workload runs.
	if id == "" && parent != nil && !isContainerRuntime(proc.GetBinary()) {
		id = startsInContainer(parent.GetBinary(), parent.GetArguments())
	}
	l.put(proc.GetExecId(), id)
	return id
}

// seed learns from an agent's whole process cache, which holds the processes
// that were running before anything was listening, and returns those it
// placed, each with its container.
func (l *containerLineage) seed(procs []*tetragon.Process) map[*tetragon.Process]string {
	byID := make(map[string]*tetragon.Process, len(procs))
	for _, p := range procs {
		if id := p.GetExecId(); id != "" {
			byID[id] = p
		}
	}
	placed := make(map[*tetragon.Process]string)
	for _, p := range procs {
		if p.GetPod() != nil {
			continue
		}
		if isContainerRuntime(p.GetBinary()) {
			continue
		}
		// Up the tree to the first ancestor that names a container. The depth
		// is bounded for a cache whose parents loop.
		id := ""
		for cur, depth := p, 0; id == "" && depth < 64; depth++ {
			if id = l.get(cur.GetParentExecId()); id != "" {
				break
			}
			par := byID[cur.GetParentExecId()]
			if par == nil || par == cur {
				break
			}
			id = startsInContainer(par.GetBinary(), par.GetArguments())
			cur = par
		}
		if id == "" {
			continue
		}
		l.put(p.GetExecId(), id)
		placed[p] = id
	}
	return placed
}

// isContainerRuntime reports whether a binary is a container runtime or the
// monitor of one: runc, crun, youki, conmon, or a runtime running from a
// sealed copy of itself, which shows as the file descriptor it was started
// from. containerd's shim is not one: the ID it carries is the sandbox's, which
// is no container of the pod.
func isContainerRuntime(binary string) bool {
	// A runtime running from a sealed copy of itself.
	if strings.HasPrefix(binary, "/dev/fd/") || strings.HasPrefix(binary, "/proc/self/fd/") ||
		strings.HasPrefix(binary, "/memfd:runc") || binary == "/proc/self/exe" {
		return true
	}
	// By name and not by a substring of the path: "truncate" has "runc" in it.
	switch base := path.Base(binary); base {
	case "runc", "crun", "youki":
		return true
	default:
		return strings.HasPrefix(base, "conmon")
	}
}

// isRuntimeInItsContainer reports whether a process Tetragon counts as a
// pod's is the runtime working on that very container. Setting a container up
// or entering it, the runtime spends a moment in the container's cgroup, and
// it is not something the workload ran.
func isRuntimeInItsContainer(p *tetragon.Process) bool {
	own := runtimeContainerID(p.GetBinary(), p.GetArguments())
	return own != "" && p.GetDocker() != "" && strings.HasPrefix(own, p.GetDocker())
}

// runtimeContainerID returns the container a runtime process is working on,
// which is on its command line.
func runtimeContainerID(binary, args string) string {
	if !isContainerRuntime(binary) {
		return ""
	}
	for _, word := range strings.Fields(args) {
		if len(word) == 64 && isHexString(word) {
			return word
		}
	}
	return ""
}

// startsInContainer returns the container that the children of a runtime
// process run in, or "" when they run on the node. A monitor's child is the
// container's first process, and what "exec" starts is in the container. What
// "create" or "run" starts directly are its hooks (a GPU runtime hook, a
// seccomp one), which run on the node on the container's behalf.
func startsInContainer(binary, args string) string {
	id := runtimeContainerID(binary, args)
	if id == "" || strings.HasPrefix(path.Base(binary), "conmon") {
		return id
	}
	for _, word := range strings.Fields(args) {
		if word == "exec" {
			return id
		}
	}
	return ""
}

// eventProcesses returns the process an event is about and its parent, and
// whether the event is the process exiting.
func eventProcesses(resp *tetragon.GetEventsResponse) (proc, parent *tetragon.Process, exit bool) {
	switch {
	case resp.GetProcessExec() != nil:
		return resp.GetProcessExec().GetProcess(), resp.GetProcessExec().GetParent(), false
	case resp.GetProcessExit() != nil:
		return resp.GetProcessExit().GetProcess(), resp.GetProcessExit().GetParent(), true
	case resp.GetProcessKprobe() != nil:
		return resp.GetProcessKprobe().GetProcess(), resp.GetProcessKprobe().GetParent(), false
	case resp.GetProcessTracepoint() != nil:
		return resp.GetProcessTracepoint().GetProcess(), resp.GetProcessTracepoint().GetParent(), false
	case resp.GetProcessUprobe() != nil:
		return resp.GetProcessUprobe().GetProcess(), resp.GetProcessUprobe().GetParent(), false
	case resp.GetProcessLsm() != nil:
		return resp.GetProcessLsm().GetProcess(), resp.GetProcessLsm().GetParent(), false
	}
	return nil, nil, false
}
