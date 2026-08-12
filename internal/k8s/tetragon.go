package k8s

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// TetragonEvent is the shape carried on the shared runtime-security event bus.
// Most events originate from Tetragon kprobes, but Cilium network policy
// denials are synthesized into the same shape so that retention, alerting and
// syslog forwarding all work off one stream. Source records the origin.
type TetragonEvent struct {
	Type       string  `json:"type"`   // "exec" | "kprobe" | "policy-deny"
	Source     string  `json:"source"` // "" (Tetragon) | "cilium"
	Time       string  `json:"time"`
	NodeName   string  `json:"nodeName"`
	Namespace  string  `json:"namespace"`
	Pod        string  `json:"pod"`
	Container  string  `json:"container"`
	Binary     string  `json:"binary"`
	Arguments  string  `json:"arguments"`
	ParentBin  string  `json:"parentBin"`
	Action     string  `json:"action"` // "monitor" | "kill" | "deny"
	PolicyName string  `json:"policyName"`
	Function   string  `json:"function"`
	FilePath   string  `json:"filePath"`             // file/path from file kprobes
	FileOp     string  `json:"fileOp"`               // "read", "write", "mmap-read", "mmap-write", "truncate"
	NetDest    string  `json:"netDest"`              // destination "addr:port" from network kprobes
	NetSrc     string  `json:"netSrc"`               // source "addr:port" from network kprobes
	DropReason string  `json:"dropReason,omitempty"` // Cilium kernel drop reason, e.g. POLICY_DENIED
	ProcessUID *uint32 `json:"processUid,omitempty"`
}

// Severity classifies an event for retention, alerting and display. Actions
// that actually prevented something — a process killed, a packet dropped —
// are critical; pure observations are warnings.
func (e TetragonEvent) Severity() string {
	if e.Blocked() {
		return "critical"
	}
	return "warning"
}

// Blocked reports whether the event represents traffic or execution that was
// prevented rather than merely observed.
func (e TetragonEvent) Blocked() bool {
	return e.Action == "kill" || e.Action == "deny"
}

// IsSecurityEvent reports whether the event belongs in the security event
// stream (persisted, alerted on, forwarded to syslog) as opposed to the raw
// process-discovery stream.
// Both origins carry a policy name by construction: kprobe events without one
// come from the base sensor and belong to process discovery, and policy
// denials are only synthesized when Hubble can name the denying policy.
func (e TetragonEvent) IsSecurityEvent() bool {
	return (e.Type == "kprobe" || e.Type == "policy-deny") && e.PolicyName != ""
}

// StreamTetragonEvents streams events from ALL Tetragon pods concurrently.
// In a multi-node cluster each pod only sees its own node's events, so we
// must aggregate all pods to get complete cluster coverage.
func (s *Store) StreamTetragonEvents(ctx context.Context, out chan<- TetragonEvent) error {
	if s.typed == nil || s.restConfig == nil {
		return fmt.Errorf("kubernetes clients not initialised")
	}

	pods, err := s.findAllTetragonPods(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, podName := range pods {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			// One pod failing must not stop the others, but it does have to be
			// visible: the error was discarded here while the comment claimed it
			// was logged, so a broken Tetragon stream looked like a quiet cluster.
			if err := s.streamFromPod(ctx, name, out); err != nil && ctx.Err() == nil {
				log.Printf("tetragon-stream: pod %s: %v", name, err)
			}
		}(podName)
	}
	wg.Wait()
	return nil
}

func (s *Store) streamFromPod(ctx context.Context, podName string, out chan<- TetragonEvent) error {
	req := s.typed.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(tetragonNamespace()).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "tetragon",
			Command:   []string{"tetra", "getevents", "-o", "json"},
			Stdin:     false,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("exec %s: %w", podName, err)
	}

	pr, pw := io.Pipe()
	defer pr.Close()

	execDone := make(chan error, 1)
	go func() {
		defer pw.Close()
		execDone <- executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: pw})
	}()

	scanner := bufio.NewScanner(pr)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		evt, ok := parseTetragonLog(scanner.Text())
		if !ok {
			continue
		}
		// For runc events with no pod context, resolve container ID → pod via K8s API.
		// For execve kprobes: evt.Binary is the exec'd binary (e.g. "bash"), not runc.
		// The container ID is still in evt.Arguments (from the calling runc process),
		// and evt.ParentBin identifies the true runc caller.
		if evt.Pod == "" && evt.Type == "kprobe" {
			checkBin := evt.Binary
			if strings.Contains(evt.ParentBin, "runc") {
				checkBin = evt.ParentBin
			}
			if cid := extractContainerIDFromRunc(checkBin, evt.Arguments); cid != "" {
				pod, ns, ctr := s.containers.resolve(ctx, s, cid)
				if pod != "" {
					evt.Pod = pod
					evt.Namespace = ns
					evt.Container = ctr
				}
			}
		}
		select {
		case out <- evt:
		case <-ctx.Done():
			return nil
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return <-execDone
}

func (s *Store) findAllTetragonPods(ctx context.Context) ([]string, error) {
	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods(tetragonNamespace()).List(ctx, metav1.ListOptions{
			LabelSelector:   sel,
			ResourceVersion: fromCache.ResourceVersion,
		})
		if err != nil {
			continue
		}
		// Only running pods can be exec'd into. Taking every pod meant a pending or
		// evicted one produced an exec failure on every reconnect.
		var names []string
		for _, p := range list.Items {
			if p.Status.Phase == corev1.PodRunning {
				names = append(names, p.Name)
			}
		}
		if len(names) > 0 {
			return names, nil
		}
	}
	return nil, fmt.Errorf("no Tetragon pods found in namespace %q (set TETRAGON_NAMESPACE if installed elsewhere)", tetragonNamespace())
}

// parseTetragonLog parses a single JSON line from tetra getevents -o json.
func parseTetragonLog(line string) (TetragonEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return TetragonEvent{}, false
	}

	evt := TetragonEvent{
		Time:     anyStr(raw, "time"),
		NodeName: anyStr(raw, "node_name", "nodeName"),
	}

	// process_exec — base sensor, no TracingPolicy needed.
	// Used by Behavior Discovery to learn process behaviors per pod.
	if execData := anyMap(raw, "process_exec", "processExec"); execData != nil {
		proc := anyMap(execData, "process")
		if proc == nil {
			return TetragonEvent{}, false
		}
		fillProcess(&evt, proc)
		if evt.Pod == "" || evt.Binary == "" {
			return TetragonEvent{}, false
		}
		evt.Type = "exec"
		evt.Action = "monitor"
		if parent := anyMap(execData, "parent"); parent != nil {
			var p TetragonEvent
			fillProcess(&p, parent)
			evt.ParentBin = p.Binary
		}
		return evt, true
	}

	// process_kprobe — triggered only by active TracingPolicies.
	kp := anyMap(raw, "process_kprobe", "processKprobe")
	if kp == nil {
		return TetragonEvent{}, false
	}

	evt.Type = "kprobe"

	fillProcess(&evt, anyMap(kp, "process"))
	// If process has no pod context (e.g. execve before the new binary is tracked),
	// fall back to parent which is the calling shell / container entrypoint.
	if evt.Pod == "" {
		var parentEvt TetragonEvent
		fillProcess(&parentEvt, anyMap(kp, "parent"))
		if parentEvt.Pod != "" {
			evt.Namespace = parentEvt.Namespace
			evt.Pod = parentEvt.Pod
			evt.Container = parentEvt.Container
		}
	}
	evt.Function = anyStr(kp, "function_name", "functionName")
	evt.PolicyName = anyStr(kp, "policy_name", "policyName")

	// Parse file path and operation for file-monitoring kprobes.
	if args, ok := kp["args"].([]any); ok {
		switch evt.Function {
		case "security_file_permission":
			evt.FilePath = fileArgPath(args, 0)
			if v := intArg(args, 1); v == 4 {
				evt.FileOp = "read"
			} else if v == 2 {
				evt.FileOp = "write"
			}
		case "security_mmap_file":
			evt.FilePath = fileArgPath(args, 0)
			if prot := uint32Arg(args, 1); prot&0x02 != 0 {
				evt.FileOp = "mmap-write"
			} else if prot&0x01 != 0 {
				evt.FileOp = "mmap-read"
			}
		case "security_path_truncate":
			evt.FilePath = pathArgPath(args, 0)
			evt.FileOp = "truncate"
		case "tcp_connect":
			evt.NetDest, evt.NetSrc = sockArgEndpoints(args, 0)
		case "inet_csk_accept":
			// kretprobe: return value (accepted socket) may be in args[0]
			evt.NetDest, evt.NetSrc = sockArgEndpoints(args, 0)
		}
	}
	// For kretprobes, Tetragon puts the return value in process_kprobe["return"]
	// as a single KprobeArgument object (map[string]any), not a slice.
	// Wrap it in a slice so sockArgEndpoints can process it at index 0.
	if evt.NetDest == "" && evt.Function == "inet_csk_accept" {
		if retVal, ok := kp["return"]; ok {
			evt.NetDest, evt.NetSrc = sockArgEndpoints([]any{retVal}, 0)
		}
		// Fallback: some versions use an array field
		if evt.NetDest == "" {
			for _, key := range []string{"returnArgs", "return_action"} {
				if retArgs, ok := kp[key].([]any); ok {
					evt.NetDest, evt.NetSrc = sockArgEndpoints(retArgs, 0)
					if evt.NetDest != "" {
						break
					}
				}
			}
		}
	}

	action := anyStr(kp, "action")
	if strings.Contains(strings.ToUpper(action), "SIGKILL") {
		evt.Action = "kill"
	} else {
		evt.Action = "monitor"
	}

	// For execve kprobes the matching is on args[0] (the binary being executed),
	// not on process.binary (which is the calling process, e.g. bash).
	// Function name varies by arch: sys_execve, __x64_sys_execve, __arm64_sys_execve, etc.
	if strings.Contains(evt.Function, "execve") {
		if args, ok := kp["args"].([]any); ok && len(args) > 0 {
			if arg0, ok := args[0].(map[string]any); ok {
				if execBin := anyStr(arg0, "string_arg", "stringArg"); execBin != "" {
					evt.ParentBin = evt.Binary // keep caller as parent
					evt.Binary = execBin
				}
			}
		}
	}

	return evt, true
}

func fillProcess(evt *TetragonEvent, proc map[string]any) {
	if proc == nil {
		return
	}
	evt.Binary = anyStr(proc, "binary")
	evt.Arguments = anyStr(proc, "arguments")
	// uid=0 (root) is the proto3 default value and is omitted from JSON;
	// treat absent uid as 0. Non-zero UIDs are always present in the JSON.
	uid := uint32(0)
	if v, ok := proc["uid"]; ok {
		if n, ok := v.(float64); ok {
			uid = uint32(n)
		}
	}
	evt.ProcessUID = &uid
	pod := anyMap(proc, "pod")
	if pod == nil {
		return
	}
	evt.Namespace = anyStr(pod, "namespace")
	evt.Pod = anyStr(pod, "name")
	if c := anyMap(pod, "container"); c != nil {
		evt.Container = anyStr(c, "name")
	}
}

func anyStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func sockArgEndpoints(args []any, idx int) (dest, src string) {
	if idx >= len(args) {
		return "", ""
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return "", ""
	}
	sock, ok := arg["sock_arg"].(map[string]any)
	if !ok {
		return "", ""
	}
	formatAddr := func(addrKey, portKey string) string {
		addr := anyStr(sock, addrKey)
		if addr == "" {
			return ""
		}
		if port, ok := sock[portKey].(float64); ok && port > 0 {
			return fmt.Sprintf("%s:%d", addr, int(port))
		}
		return addr
	}
	return formatAddr("daddr", "dport"), formatAddr("saddr", "sport")
}

func fileArgPath(args []any, idx int) string {
	if idx >= len(args) {
		return ""
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return ""
	}
	if f, ok := arg["file_arg"].(map[string]any); ok {
		return anyStr(f, "path")
	}
	return ""
}

func pathArgPath(args []any, idx int) string {
	if idx >= len(args) {
		return ""
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return ""
	}
	if p, ok := arg["path_arg"].(map[string]any); ok {
		return anyStr(p, "path")
	}
	return ""
}

func intArg(args []any, idx int) int {
	if idx >= len(args) {
		return 0
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return 0
	}
	if v, ok := arg["int_arg"].(float64); ok {
		return int(v)
	}
	return 0
}

func uint32Arg(args []any, idx int) uint32 {
	if idx >= len(args) {
		return 0
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return 0
	}
	if v, ok := arg["uint32_arg"].(float64); ok {
		return uint32(v)
	}
	return 0
}

func anyMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if sub, ok := v.(map[string]any); ok {
				return sub
			}
		}
	}
	return nil
}
