package handler

import (
	"context"
	"testing"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// findEdge returns the single edge between two pods, or nil.
func findEdge(resp TopologyResponse, src, dst string) *TopologyEdge {
	for i := range resp.Edges {
		if resp.Edges[i].Source == src && resp.Edges[i].Target == dst {
			return &resp.Edges[i]
		}
	}
	return nil
}

// build runs the topology builder over a fixed set of buffer entries. ipMap is
// left empty so pruning is skipped — these tests are about verdict selection.
func build(t *testing.T, entries []k8s.CiliumTopoEntry) TopologyResponse {
	t.Helper()
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest(entries)
	return buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)
}

func entry(key, verdict string, seen time.Time) k8s.CiliumTopoEntry {
	return k8s.CiliumTopoEntry{
		Key:   key,
		SrcNs: "demo", SrcPod: "client",
		DstNs: "demo", DstPod: "server",
		Port:     "80",
		Verdict:  verdict,
		Count:    1,
		LastSeen: seen,
	}
}

// The case that sent an operator looking: the policy was deleted, traffic now
// flows, and the graph still showed a red edge — because "blocked wins" also
// suppressed the allowed edge that replaced it, for as long as the 24h buffer
// held the stale denial.
func TestNewerAllowedTrafficReplacesAStaleDenial(t *testing.T) {
	now := time.Now()
	resp := build(t, []k8s.CiliumTopoEntry{
		entry("a", "dropped", now.Add(-2*time.Hour)),
		entry("b", "allowed", now.Add(-1*time.Minute)),
	})

	e := findEdge(resp, "demo/client", "demo/server")
	if e == nil {
		t.Fatal("no edge between the two pods")
	}
	if e.Blocked {
		t.Error("edge is still blocked; the newer allowed flow should have replaced the denial")
	}
	if len(resp.Edges) != 1 {
		t.Errorf("got %d edges, want 1 — the pair must not render twice", len(resp.Edges))
	}
}

// The reverse still has to work, or applying a policy would not turn the edge red
// while older allowed flows sit in the buffer.
func TestNewerDenialReplacesAllowedTraffic(t *testing.T) {
	now := time.Now()
	resp := build(t, []k8s.CiliumTopoEntry{
		entry("a", "allowed", now.Add(-2*time.Hour)),
		entry("b", "dropped", now.Add(-1*time.Minute)),
	})

	e := findEdge(resp, "demo/client", "demo/server")
	if e == nil {
		t.Fatal("no edge between the two pods")
	}
	if !e.Blocked {
		t.Error("edge is not blocked; the newer denial should have replaced the allowed flow")
	}
}

// Of the two, a denial is the one worth surfacing.
func TestTieGoesToTheDenial(t *testing.T) {
	at := time.Now().Add(-time.Minute)
	resp := build(t, []k8s.CiliumTopoEntry{
		entry("a", "allowed", at),
		entry("b", "dropped", at),
	})

	e := findEdge(resp, "demo/client", "demo/server")
	if e == nil {
		t.Fatal("no edge between the two pods")
	}
	if !e.Blocked {
		t.Error("a tie should render as blocked")
	}
}
