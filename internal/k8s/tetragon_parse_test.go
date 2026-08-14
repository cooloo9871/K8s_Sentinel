package k8s

import "testing"

// A TracingPolicy can attach to four hook kinds, and all of them have to come
// out of the parser as security events — a hook the parser drops is a policy
// that fires with nothing to show for it. The JSON shapes follow Tetragon's
// GetEventsResponse; field names appear in both snake_case (tetra getevents)
// and camelCase (proto JSON), so both are exercised.

const procJSON = `"process":{"binary":"/usr/bin/curl","arguments":"http://x",` +
	`"pod":{"namespace":"demo","name":"web-1","container":{"name":"app"}}}`

func TestParsesATracepointEvent(t *testing.T) {
	evt, ok := parseTetragonLog(`{"process_tracepoint":{` + procJSON + `,` +
		`"subsys":"raw_syscalls","event":"sys_enter","policy_name":"tp-watch",` +
		`"action":"KPROBE_ACTION_POST"},"node_name":"n1","time":"2026-08-14T05:00:00Z"}`)
	if !ok {
		t.Fatal("tracepoint event was dropped by the parser")
	}
	if evt.Type != "tracepoint" {
		t.Errorf("type = %q, want tracepoint", evt.Type)
	}
	// The trigger point rides in Function whichever hook kind it is, so
	// dedup, filtering and the detail panel need no per-kind handling.
	if evt.Function != "raw_syscalls/sys_enter" {
		t.Errorf("function = %q, want raw_syscalls/sys_enter", evt.Function)
	}
	if evt.Pod != "web-1" || evt.PolicyName != "tp-watch" {
		t.Errorf("pod/policy = %q/%q", evt.Pod, evt.PolicyName)
	}
	if !evt.IsSecurityEvent() {
		t.Error("a policy-named tracepoint event is not a security event")
	}
	if evt.Severity() != "warning" {
		t.Errorf("severity = %q, want warning for a Post action", evt.Severity())
	}
}

func TestParsesAUprobeEvent(t *testing.T) {
	evt, ok := parseTetragonLog(`{"processUprobe":{` + procJSON + `,` +
		`"path":"/usr/lib/libssl.so","symbol":"SSL_write","policyName":"ssl-watch"},` +
		`"nodeName":"n1","time":"2026-08-14T05:00:00Z"}`)
	if !ok {
		t.Fatal("uprobe event was dropped by the parser")
	}
	if evt.Type != "uprobe" {
		t.Errorf("type = %q, want uprobe", evt.Type)
	}
	if evt.Function != "/usr/lib/libssl.so:SSL_write" {
		t.Errorf("function = %q", evt.Function)
	}
	if !evt.IsSecurityEvent() {
		t.Error("a policy-named uprobe event is not a security event")
	}
}

// An LSM hook with Override forced the call to return an error: the operation
// was blocked, not observed, and anything less than critical would report an
// enforcing policy as a bystander.
func TestParsesAnLSMOverrideAsBlocked(t *testing.T) {
	evt, ok := parseTetragonLog(`{"process_lsm":{` + procJSON + `,` +
		`"function_name":"file_open","policy_name":"lsm-guard",` +
		`"action":"KPROBE_ACTION_OVERRIDE"},"node_name":"n1","time":"2026-08-14T05:00:00Z"}`)
	if !ok {
		t.Fatal("LSM event was dropped by the parser")
	}
	if evt.Type != "lsm" || evt.Function != "file_open" {
		t.Errorf("type/function = %q/%q", evt.Type, evt.Function)
	}
	if evt.Action != "deny" {
		t.Errorf("action = %q, want deny for an Override", evt.Action)
	}
	if !evt.Blocked() || evt.Severity() != "critical" {
		t.Errorf("blocked/severity = %v/%q, want true/critical", evt.Blocked(), evt.Severity())
	}
}

// The kprobe path shares the action mapping, so an errno-injecting kprobe
// reads as blocked the same way an LSM one does.
func TestKprobeOverrideAlsoReadsAsBlocked(t *testing.T) {
	evt, ok := parseTetragonLog(`{"process_kprobe":{` + procJSON + `,` +
		`"function_name":"security_file_permission","policy_name":"file-guard",` +
		`"action":"KPROBE_ACTION_OVERRIDE"},"time":"2026-08-14T05:00:00Z"}`)
	if !ok {
		t.Fatal("kprobe event was dropped by the parser")
	}
	if evt.Action != "deny" || evt.Severity() != "critical" {
		t.Errorf("action/severity = %q/%q, want deny/critical", evt.Action, evt.Severity())
	}
}

// The pre-existing contract, pinned: SIGKILL is a kill, and a hook event
// without a policy name comes from the base sensor and is not a security event.
func TestKprobeBaseline(t *testing.T) {
	evt, ok := parseTetragonLog(`{"process_kprobe":{` + procJSON + `,` +
		`"function_name":"tcp_connect","policy_name":"net-watch",` +
		`"action":"KPROBE_ACTION_SIGKILL"},"time":"2026-08-14T05:00:00Z"}`)
	if !ok || evt.Action != "kill" || evt.Severity() != "critical" {
		t.Errorf("ok/action/severity = %v/%q/%q, want true/kill/critical", ok, evt.Action, evt.Severity())
	}

	evt, ok = parseTetragonLog(`{"process_tracepoint":{` + procJSON + `,` +
		`"subsys":"raw_syscalls","event":"sys_enter"},"time":"2026-08-14T05:00:00Z"}`)
	if !ok {
		t.Fatal("policy-less tracepoint event was dropped instead of parsed")
	}
	if evt.IsSecurityEvent() {
		t.Error("a hook event with no policy name must not enter the security stream")
	}
}
