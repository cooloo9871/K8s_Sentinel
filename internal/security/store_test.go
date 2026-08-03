package security

import (
	"testing"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// Two attempts at the same denied destination differ only by the kernel-assigned
// source port, so they must dedup into one event with a count — otherwise a pod
// retrying in a loop fills the list with one repeated denial.
func TestSameEventIgnoresEphemeralSourcePort(t *testing.T) {
	stored := Event{
		Namespace: "net-lab", Pod: "traffic-generator", Function: "cilium-egress-deny",
		PolicyName: "deny-tg-to-echo", Action: "deny",
		NetDest: "10.0.0.21:80", NetSrc: "10.0.1.235:60524",
	}
	retry := k8s.TetragonEvent{
		Namespace: "net-lab", Pod: "traffic-generator", Function: "cilium-egress-deny",
		PolicyName: "deny-tg-to-echo", Action: "deny",
		NetDest: "10.0.0.21:80", NetSrc: "10.0.1.235:41337",
	}
	if !sameEvent(stored, retry) {
		t.Error("retry with a new source port was treated as a different event")
	}

	// A different destination port is a genuinely different denial.
	other := retry
	other.NetDest = "10.0.0.21:443"
	if sameEvent(stored, other) {
		t.Error("a different destination port was deduped away")
	}
}

func TestCollapseEphemeralPortLeavesServicePorts(t *testing.T) {
	cases := map[string]string{
		"10.0.1.235:60524": "10.0.1.235:dynamic",
		"10.0.0.21:80":     "10.0.0.21:80",
		"10.0.0.21:8080":   "10.0.0.21:8080",
		"10.0.0.21":        "10.0.0.21",
		"fe80::1":          "fe80::1",
	}
	for in, want := range cases {
		if got := collapseEphemeralPort(in); got != want {
			t.Errorf("collapseEphemeralPort(%q) = %q, want %q", in, got, want)
		}
	}
}
