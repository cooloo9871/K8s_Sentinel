package rsyslog

import "testing"

// The syslog type= field says what the rule governs, and SIEM rules key on it.
// This was the fourth divergent copy of the classifier — it forwarded LSM and
// tracepoint events as type=process while the badge, CSV and alerts said
// File/Network/Kernel.
func TestSecurityRuleTypeAgreesWithTheUI(t *testing.T) {
	cases := map[string]string{
		"tcp_connect":              "network",
		"inet_csk_accept":          "network",
		"socket_connect":           "network",
		"cilium-egress-deny":       "network",
		"security_file_permission": "file",
		"security_mmap_file":       "file",
		"file_open":                "file",
		"__x64_sys_execve":         "process",
		"raw_syscalls/sys_enter":   "kernel",
		"bpf":                      "kernel",
		// Events with no function predate the hook kinds; keep their label.
		"": "process",
	}
	for fn, want := range cases {
		if got := securityRuleType(fn); got != want {
			t.Errorf("securityRuleType(%q) = %q, want %q", fn, got, want)
		}
	}
}
