package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podEndpoint is a running pod reachable over gRPC: its name for logging, its
// IP to dial. Each Tetragon agent only observes its own node, so every one is
// connected to.
type podEndpoint struct {
	Name string
	IP   string
	Node string // the node this agent runs on; the ingestion-health key
}

// tetragonGRPCPort is where the Tetragon agent's gRPC server listens. The
// install sets tetragon.grpc.address=0.0.0.0:54321 so it is reachable on the
// pod network; the default localhost bind is not.
func tetragonGRPCPort() string {
	return envOr("TETRAGON_GRPC_PORT", "54321")
}

// IsMonitoringPort reports whether a port is one Sentinel itself dials to
// collect events — the Tetragon gRPC API. It is a real destination port but
// sits in the ephemeral range (54321), so the topology must not collapse it to
// "dynamic" the way it does genuine client-side ports.
func IsMonitoringPort(port string) bool {
	return port == tetragonGRPCPort()
}

// TetragonEvent is the shape carried on the shared runtime-security event bus.
// Most events originate from Tetragon kprobes, but Cilium network policy
// denials are synthesized into the same shape so that retention, alerting and
// syslog forwarding all work off one stream. Source records the origin.
type TetragonEvent struct {
	// "exec" | "kprobe" | "tracepoint" | "uprobe" | "lsm" | "policy-deny".
	// The four hook kinds are what a TracingPolicy can attach to; they differ
	// in how the trigger point is named, and Function carries that name in one
	// string whichever kind it is.
	Type       string  `json:"type"`
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
// Every origin carries a policy name by construction: hook events without one
// come from the base sensor and belong to process discovery, and policy
// denials are only synthesized when Hubble can name the denying policy.
func (e TetragonEvent) IsSecurityEvent() bool {
	return (e.HookKind() != "" || e.Type == "policy-deny") && e.PolicyName != ""
}

// HookKind names the hook that produced the event — kprobe, tracepoint, uprobe
// or lsm — and is empty for everything else: an exec from the base sensor and a
// policy denial synthesized from Hubble are not hooks. The one place the hook
// kinds are enumerated.
func (e TetragonEvent) HookKind() string {
	switch e.Type {
	case "kprobe", "tracepoint", "uprobe", "lsm":
		return e.Type
	}
	return ""
}

// StreamTetragonEvents streams events from ALL Tetragon pods concurrently over
// their gRPC APIs. In a multi-node cluster each pod only sees its own node's
// events, so every one is connected to for complete cluster coverage.
func (s *Store) StreamTetragonEvents(ctx context.Context, out chan<- TetragonEvent) error {
	if s.typed == nil {
		return fmt.Errorf("kubernetes clients not initialised")
	}

	pods, err := s.findAllTetragonPods(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, pod := range pods {
		wg.Add(1)
		go func(p podEndpoint) {
			defer wg.Done()
			// One pod failing must not stop the others, but it does have to be
			// visible: a broken Tetragon stream otherwise looks like a quiet
			// cluster.
			if err := s.streamFromPod(ctx, p, out); err != nil && ctx.Err() == nil {
				log.Printf("tetragon-stream: pod %s: %v", p.Name, err)
			}
		}(pod)
	}
	wg.Wait()
	return nil
}

func (s *Store) streamFromPod(ctx context.Context, pod podEndpoint, out chan<- TetragonEvent) error {
	conn, err := dialGRPC("TETRAGON_GRPC", pod.IP+":"+tetragonGRPCPort())
	if err != nil {
		s.ingestion.MarkTetragonError(pod.Node, err)
		return fmt.Errorf("dial %s: %w", pod.Name, err)
	}
	defer conn.Close()

	stream, err := tetragon.NewFineGuidanceSensorsClient(conn).GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		s.ingestion.MarkTetragonError(pod.Node, err)
		return fmt.Errorf("GetEvents %s: %w", pod.Name, err)
	}
	// The stream is open; from here the agent is genuinely reachable, which
	// pod readiness alone never told us.
	s.ingestion.MarkTetragonConnected(pod.Node)

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.ingestion.MarkTetragonError(pod.Node, err)
			return fmt.Errorf("recv from %s: %w", pod.Name, err)
		}
		// A received message means the stream is live and delivering, the
		// heartbeat that distinguishes a quiet cluster from a broken one.
		s.ingestion.MarkTetragonEvent(pod.Node)
		// The gRPC message is bridged through the same parser the CLI JSON used,
		// by marshaling it exactly as `tetra getevents -o json` does.
		line, err := marshalJSON(resp)
		if err != nil {
			continue
		}
		evt, ok := parseTetragonLog(line)
		if !ok {
			continue
		}
		// For runc events with no pod context, resolve container ID → pod via K8s API.
		// For execve kprobes: evt.Binary is the exec'd binary (e.g. "bash"), not runc.
		// The container ID is still in evt.Arguments (from the calling runc process),
		// and evt.ParentBin identifies the true runc caller.
		if evt.Pod == "" && evt.HookKind() != "" {
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
}

func (s *Store) findAllTetragonPods(ctx context.Context) ([]podEndpoint, error) {
	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods(tetragonNamespace()).List(ctx, metav1.ListOptions{
			LabelSelector:   sel,
			ResourceVersion: fromCache.ResourceVersion,
		})
		if err != nil {
			continue
		}
		// Only running pods with an assigned IP can be dialled; a pending or
		// terminating one has none and would fail the connection on every
		// reconnect.
		var pods []podEndpoint
		for _, p := range list.Items {
			if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
				node := p.Spec.NodeName
				if node == "" {
					node = p.Name // fall back so the key is never empty
				}
				pods = append(pods, podEndpoint{Name: p.Name, IP: p.Status.PodIP, Node: node})
			}
		}
		if len(pods) > 0 {
			return pods, nil
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

	// The other hook kinds a TracingPolicy can attach to. Same process context
	// and pipeline as a kprobe; only the naming of the trigger point differs,
	// and Function carries it in one string so deduplication, filtering and the
	// detail panel work identically. Their arguments are not decoded — every
	// hook's args mean something different, and a generic dump is noise.
	if tp := anyMap(raw, "process_tracepoint", "processTracepoint"); tp != nil {
		hookEvent(&evt, "tracepoint", tp)
		evt.Function = strings.Trim(anyStr(tp, "subsys")+"/"+anyStr(tp, "event"), "/")
		return evt, true
	}
	if up := anyMap(raw, "process_uprobe", "processUprobe"); up != nil {
		hookEvent(&evt, "uprobe", up)
		evt.Function = strings.Trim(anyStr(up, "path")+":"+anyStr(up, "symbol"), ":")
		return evt, true
	}
	if lsm := anyMap(raw, "process_lsm", "processLsm"); lsm != nil {
		hookEvent(&evt, "lsm", lsm)
		evt.Function = anyStr(lsm, "function_name", "functionName")
		// The object of the call, for the hooks whose args carry one — LSM
		// reuses the kprobe argument shapes, so the same decoders apply. Left
		// undecoded, the detail panel's File and Destination stay blank and the
		// only clue is the process's own command line.
		if args, ok := lsm["args"].([]any); ok {
			switch evt.Function {
			case "file_open":
				if p := fileArgPath(args, 0); p != "" {
					evt.FilePath, evt.FileOp = p, "open"
				}
			case "file_permission":
				evt.FilePath, evt.FileOp = filePermissionArgs(args)
			case "socket_connect", "socket_bind":
				evt.NetDest = sockaddrArgDest(args)
			}
		}
		return evt, true
	}

	// process_kprobe — triggered only by active TracingPolicies.
	kp := anyMap(raw, "process_kprobe", "processKprobe")
	if kp == nil {
		return TetragonEvent{}, false
	}

	hookEvent(&evt, "kprobe", kp)
	evt.Function = anyStr(kp, "function_name", "functionName")

	// Parse file path and operation for file-monitoring kprobes.
	if args, ok := kp["args"].([]any); ok {
		switch evt.Function {
		case "security_file_permission":
			evt.FilePath, evt.FileOp = filePermissionArgs(args)
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

// hookAction turns Tetragon's action string into this store's verb. Sigkill
// killed the process outright; Signal sends one (enforcement uses 9) and
// NotifyEnforcer hands the kill to the enforcer program; Override forced the
// call to return an error, blocking the operation without killing anything.
// Every one of them prevented something, and must read as blocked rather than
// as a pure observation.
func hookAction(action string) string {
	a := strings.ToUpper(action)
	switch {
	case strings.Contains(a, "SIGKILL"), strings.Contains(a, "SIGNAL"),
		strings.Contains(a, "NOTIFYENFORCER"):
		return "kill"
	case strings.Contains(a, "OVERRIDE"):
		return "deny"
	default:
		return "monitor"
	}
}

// hookEvent fills what every hook kind shares — the process context, the
// policy that fired, and the action taken — so the four branches cannot drift
// on any of them.
func hookEvent(evt *TetragonEvent, kind string, hook map[string]any) {
	evt.Type = kind
	fillProcessWithParentFallback(evt, hook)
	evt.PolicyName = anyStr(hook, "policy_name", "policyName")
	evt.Action = hookAction(anyStr(hook, "action"))
}

// filePermissionArgs decodes the (file, mask) pair that both file_permission
// hooks carry — the security_file_permission kprobe and the LSM hook use the
// same shape and the same mask values: 4 is read, 2 is write.
func filePermissionArgs(args []any) (path, op string) {
	path = fileArgPath(args, 0)
	if v := intArg(args, 1); v == 4 {
		op = "read"
	} else if v == 2 {
		op = "write"
	}
	return path, op
}

// fillProcessWithParentFallback fills the process context, falling back to the
// parent — the calling shell or container entrypoint — when the process itself
// has no pod yet (e.g. execve before the new binary is tracked).
func fillProcessWithParentFallback(evt *TetragonEvent, hook map[string]any) {
	fillProcess(evt, anyMap(hook, "process"))
	if evt.Pod == "" {
		var parentEvt TetragonEvent
		fillProcess(&parentEvt, anyMap(hook, "parent"))
		if parentEvt.Pod != "" {
			evt.Namespace = parentEvt.Namespace
			evt.Pod = parentEvt.Pod
			evt.Container = parentEvt.Container
		}
	}
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
	sock := anyMap(arg, "sock_arg", "sockArg")
	if sock == nil {
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

// sockaddrArgDest finds the sockaddr argument and formats its address:port.
// LSM socket hooks receive a sockaddr rather than a sock, and the field names
// vary by Tetragon version (addr/port, sin_addr/sin_port) — all are accepted.
func sockaddrArgDest(args []any) string {
	for _, a := range args {
		arg, ok := a.(map[string]any)
		if !ok {
			continue
		}
		sa := anyMap(arg, "sockaddr_arg", "sockaddrArg")
		if sa == nil {
			continue
		}
		addr := anyStr(sa, "addr", "sin_addr", "sinAddr")
		// An AF_UNIX peer or an unrecognised field name — the address may sit
		// in the next argument, so keep scanning rather than giving up.
		if addr == "" {
			continue
		}
		for _, k := range []string{"port", "sin_port", "sinPort"} {
			if p, ok := sa[k].(float64); ok && p > 0 {
				return fmt.Sprintf("%s:%d", addr, int(p))
			}
		}
		return addr
	}
	return ""
}

func fileArgPath(args []any, idx int) string {
	if idx >= len(args) {
		return ""
	}
	arg, ok := args[idx].(map[string]any)
	if !ok {
		return ""
	}
	if f := anyMap(arg, "file_arg", "fileArg"); f != nil {
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
	if p := anyMap(arg, "path_arg", "pathArg"); p != nil {
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
	for _, k := range []string{"int_arg", "intArg"} {
		if v, ok := arg[k].(float64); ok {
			return int(v)
		}
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
	for _, k := range []string{"uint32_arg", "uint32Arg"} {
		if v, ok := arg[k].(float64); ok {
			return uint32(v)
		}
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
