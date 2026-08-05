package security

import (
	"testing"
	"time"

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

// A pod retrying in a loop refreshes the same row indefinitely, so a field that
// was empty when the row was first recorded must still be able to arrive later —
// otherwise a row predating the container lookup could never acquire one.
func TestDedupFillsFieldsMissingFromTheStoredEvent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir + "/events.json")

	now := time.Now().UTC()
	base := k8s.TetragonEvent{
		Type: "policy-deny", Time: now.Format(time.RFC3339Nano),
		Namespace: "net-lab", Pod: "traffic-generator-9b649846d-bxqfc",
		Function: "cilium-egress-deny", PolicyName: "deny-tg-to-echo", Action: "deny",
		NetDest: "10.0.0.21:80", NetSrc: "10.0.1.235:60524",
	}
	s.Add(base) // recorded without a container, as pre-v0.2.6 events were

	next := base
	next.Time = now.Add(2 * time.Second).Format(time.RFC3339Nano)
	next.NetSrc = "10.0.1.235:41337" // new ephemeral port, same logical denial
	next.Container = "traffic-generator"
	next.DropReason = "POLICY_DENY"
	s.Add(next)

	// The store writes asynchronously; without this the test can finish while a
	// write is landing and race with the cleanup of its own temporary directory.
	s.WaitForFlush()

	evts := s.List()
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1 deduped", len(evts))
	}
	if evts[0].Count != 2 {
		t.Errorf("count = %d, want 2", evts[0].Count)
	}
	if evts[0].Container != "traffic-generator" {
		t.Errorf("container = %q, want it filled in from the later sighting", evts[0].Container)
	}
	if evts[0].DropReason != "POLICY_DENY" {
		t.Errorf("dropReason = %q, want it filled in", evts[0].DropReason)
	}
}
