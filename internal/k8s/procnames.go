package k8s

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// A process that was running before Tetragon started is one Tetragon never saw
// being executed. It reads the process from /proc instead, where the kernel
// keeps the file that was loaded and not the path it was started by: "sleep"
// that is a link to a multi-call binary comes back as "coreutils", "/bin/sh"
// as "dash". Policies match the path a process is started by, so a profile
// learned from those names allows the wrong thing the next time the pod
// starts. Tetragon drops the one place the started-by name survives, the first
// word of the command line, and offers no way to ask for it.
//
// So for those processes, and only those, the name is read on the node, by
// running a script in the Tetragon container, which has the node's /proc. The
// script is fixed, and takes nothing but process IDs.

// procNamesScript reads process IDs, one a line, and for each prints the ID,
// the file /proc says it runs, and the path it was started by, tab-separated.
// A bare name is looked up the way the runtime or shell that started it did:
// through the PATH of the process, inside its own root. A link counts as
// found without being followed, since an absolute one would be followed in
// the wrong root. A process whose command line is not a path that exists (one
// that rewrote its title, a relative path) prints nothing.
const procNamesScript = "# " + procNamesMark + `
P=/procRoot; [ -d $P/1 ] || P=/proc
while read -r pid; do
  d=$P/$pid; a0=; r=
  { IFS= read -r -d '' a0 < $d/cmdline; } 2>/dev/null
  [ -n "$a0" ] || continue
  exe=$(readlink $d/exe 2>/dev/null) || continue
  case $a0 in
    /*) f=$d/root$a0
        if [ -L "$f" ] || { [ -f "$f" ] && [ -x "$f" ]; }; then r=$a0; fi ;;
    */*) ;;
    *) path=$(tr '\0' '\n' < $d/environ 2>/dev/null | sed -n 's/^PATH=//p' | head -n1)
       [ -n "$path" ] || path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
       oldifs=$IFS; IFS=:
       for dir in $path; do
         case $dir in /*) ;; *) continue ;; esac
         f=$d/root$dir/$a0
         if [ -L "$f" ] || { [ -f "$f" ] && [ -x "$f" ]; }; then r=$dir/$a0; break; fi
       done
       IFS=$oldifs ;;
  esac
  [ -n "$r" ] && printf '%s\t%s\t%s\n' "$pid" "$exe" "$r"
done
exit 0
`

// procNamesMark opens the script, and so is on the command line of the shell
// running it: how its own commands are told from the agent's.
const procNamesMark = "sentinel-started-by"

// isOwnProcNames reports whether a process is the script or one of the
// commands it runs, which are no part of what the Tetragon pod does.
func isOwnProcNames(proc, parent *tetragon.Process) bool {
	return strings.Contains(proc.GetArguments(), procNamesMark) ||
		strings.Contains(parent.GetArguments(), procNamesMark)
}

// startedBy is one line of the script's output.
type startedBy struct {
	exe  string // what /proc/<pid>/exe points at
	path string // the path the process was started by
}

// scannedFromProc reports whether Tetragon learned of a process by reading
// /proc rather than by seeing it executed.
func scannedFromProc(p *tetragon.Process) bool {
	return strings.Contains(p.GetFlags(), "procFS")
}

func parseProcNames(out []byte) map[uint32]startedBy {
	names := make(map[uint32]startedBy)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || !strings.HasPrefix(f[2], "/") {
			continue
		}
		pid, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			continue
		}
		names[uint32(pid)] = startedBy{exe: f[1], path: f[2]}
	}
	return names
}

// renameStartedBy gives each process the path it was started by. The file is
// compared with the one Tetragon read, so that a process ID that has since
// gone to another program changes nothing.
func renameStartedBy(procs []*tetragon.Process, names map[uint32]startedBy) {
	for _, p := range procs {
		if p.GetPid() == nil {
			continue
		}
		if n, ok := names[p.GetPid().GetValue()]; ok && n.exe == p.GetBinary() {
			p.Binary = n.path
		}
	}
}

// procNames runs the script in one Tetragon agent for the given processes.
func (s *Store) procNames(ctx context.Context, agent podEndpoint, procs []*tetragon.Process) (map[uint32]startedBy, error) {
	if s.restCfg == nil || s.typed == nil {
		return nil, fmt.Errorf("no cluster connection")
	}
	var stdin bytes.Buffer
	for _, p := range procs {
		if p.GetPid() != nil {
			fmt.Fprintln(&stdin, p.GetPid().GetValue())
		}
	}
	if stdin.Len() == 0 {
		return nil, nil
	}
	url := s.typed.CoreV1().RESTClient().Post().Resource("pods").
		Namespace(tetragonNamespace()).Name(agent.Name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "tetragon",
			Command:   []string{"sh", "-c", procNamesScript},
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec).URL()

	// WebSocket first, then SPDY for the API servers that have no other.
	spdy, err := remotecommand.NewSPDYExecutor(s.restCfg, "POST", url)
	if err != nil {
		return nil, err
	}
	exec := spdy
	if ws, err := remotecommand.NewWebSocketExecutor(s.restCfg, "GET", url.String()); err == nil {
		if both, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		}); err == nil {
			exec = both
		}
	}

	execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if err := exec.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdin: &stdin, Stdout: &stdout, Stderr: &stderr,
	}); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, firstLine(msg))
		}
		return nil, err
	}
	return parseProcNames(stdout.Bytes()), nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
