package alert

import "testing"

// The label says what the rule governs. Content wins — a decoded destination
// or path is unambiguous — and only process hooks fall back to "Process Rule";
// everything else is a kernel hook, not an execution.
func TestRuleTypeLabelsWhatTheRuleGoverns(t *testing.T) {
	cases := []struct {
		name string
		p    WebhookPayload
		want string
	}{
		{"network by destination", WebhookPayload{NetDest: "10.0.0.5:443"}, "Network Rule"},
		{"file by path", WebhookPayload{FilePath: "/etc/shadow", Function: "file_open"}, "File Rule"},
		{"process by function", WebhookPayload{Function: "__x64_sys_execve"}, "Process Rule"},
		// A raw tracepoint with nothing decoded is not an execution — labelling
		// it "Process Rule" sent readers hunting for one.
		{"tracepoint falls to kernel", WebhookPayload{Function: "raw_syscalls/sys_enter"}, "Kernel Rule"},
		{"undecoded lsm falls to kernel", WebhookPayload{Function: "bpf"}, "Kernel Rule"},
		// Events with no function at all predate the hook kinds; keep their
		// historical label.
		{"no function stays process", WebhookPayload{}, "Process Rule"},
	}
	for _, c := range cases {
		if got := ruleType(c.p); got != c.want {
			t.Errorf("%s: ruleType = %q, want %q", c.name, got, c.want)
		}
	}
}
