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

// An L7 denial means L3/L4 passed: the connection is permitted and only the
// request is refused, so Hubble reports both verdicts for the same pair at the
// same time. Picking the newer one showed the allow and hid the denial, which is
// the one thing the operator needs to see.
func TestALiveL7DenialWinsOverTheAllowedConnection(t *testing.T) {
	now := time.Now()
	resp := build(t, []k8s.CiliumTopoEntry{
		// The allowed L3/L4 flow keeps arriving, so it is always the newer one.
		entry("a", "allowed", now.Add(-1*time.Second)),
		entry("b", "dropped", now.Add(-5*time.Second)),
	})

	e := findEdge(resp, "demo/client", "demo/server")
	if e == nil {
		t.Fatal("no edge between the two pods")
	}
	if !e.Blocked {
		t.Error("the live denial was hidden by the allowed connection it rides on")
	}
	if len(resp.Edges) != 1 {
		t.Errorf("got %d edges, want 1", len(resp.Edges))
	}
}

// The case the recency rule was written for still has to work: once a policy is
// deleted the drops stop, and the traffic now flowing takes the edge back.
func TestADenialThatStoppedGivesWayToCurrentTraffic(t *testing.T) {
	now := time.Now()
	resp := build(t, []k8s.CiliumTopoEntry{
		entry("a", "dropped", now.Add(-10*time.Minute)),
		entry("b", "allowed", now.Add(-2*time.Second)),
	})

	e := findEdge(resp, "demo/client", "demo/server")
	if e == nil {
		t.Fatal("no edge between the two pods")
	}
	if e.Blocked {
		t.Error("a denial that stopped ten minutes ago is still shown")
	}
}

// A cluster quiet for longer than the window looks identical to one where Hubble
// delivers nothing, and only one of those needs the install instructions. The
// response has to carry the difference.
func TestResponseSaysWhetherAnyFlowWasEverSeen(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	resp := buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)
	if resp.FlowsEverSeen {
		t.Error("a store that never received a flow reports otherwise")
	}

	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{entry("a", "allowed", time.Now())})
	resp = buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)
	if !resp.FlowsEverSeen {
		t.Error("a store holding a flow reports that none was ever seen")
	}
}

func nodeEntry(key, srcIP, dstNs, dstPod string, seen time.Time) k8s.CiliumTopoEntry {
	return k8s.CiliumTopoEntry{
		Key: key, SrcIP: srcIP, DstNs: dstNs, DstPod: dstPod,
		Port: "80", Verdict: "allowed", Count: 1, LastSeen: seen,
	}
}

// Cilium SNATs inbound NodePort traffic to the ingress node's cilium_host when
// the backend pod is on another node. That address used to be hidden, which did
// not hide a node — it dropped the whole edge, losing the fact that something
// outside the cluster reached a workload.
func TestInboundTrafficViaCiliumHostReachesTheGraph(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{
		nodeEntry("a", "10.0.1.1", "demo", "nginx", time.Now()),
	})
	nodeIPs := k8s.NodeIPMap{IPToName: map[string]string{"10.0.1.1": "worker-1"}}

	resp := buildCiliumTopology(context.Background(), store, nil, nodeIPs, nil, false)
	e := findEdge(resp, "node:10.0.1.1", "demo/nginx")
	if e == nil {
		t.Fatalf("inbound edge missing; got %d edges", len(resp.Edges))
	}
	for _, n := range resp.Nodes {
		if n.ID == "node:10.0.1.1" && n.Label != "worker-1" {
			t.Errorf("node label = %q, want the node name", n.Label)
		}
	}
}

// The chatter that hiding cilium_host was meant to suppress is between node
// addresses, and that is still suppressed — by what it is, not by hiding one end.
func TestNodeToNodeChatterStaysOut(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{{
		Key: "a", SrcIP: "10.0.1.1", DstIP: "10.0.2.1",
		Port: "4240", Verdict: "allowed", Count: 1, LastSeen: time.Now(),
	}})
	nodeIPs := k8s.NodeIPMap{IPToName: map[string]string{
		"10.0.1.1": "worker-1", "10.0.2.1": "worker-2",
	}}

	resp := buildCiliumTopology(context.Background(), store, nil, nodeIPs, nil, false)
	if len(resp.Edges) != 0 {
		t.Errorf("got %d edges, want none — node to node is plumbing", len(resp.Edges))
	}
}

// Identity outranks the address: an external source whose IP was rewritten to a
// node's must not read as the node, or the graph says a node initiated traffic
// that came from outside.
func TestAWorldSourceStaysExternalEvenWithANodeAddress(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{{
		Key: "a", SrcIP: "10.0.0.181", SrcIsWorld: true,
		DstNs: "default", DstPod: "nginx",
		Port: "80", Verdict: "allowed", Count: 1, LastSeen: time.Now(),
	}})
	nodeIPs := k8s.NodeIPMap{IPToName: map[string]string{"10.0.0.181": "cilium-w0"}}

	resp := buildCiliumTopology(context.Background(), store, nil, nodeIPs, nil, false)
	e := findEdge(resp, "ext:10.0.0.181", "default/nginx")
	if e == nil {
		t.Fatalf("external edge missing; got %d edges", len(resp.Edges))
	}
	for _, n := range resp.Nodes {
		if n.ID != "ext:10.0.0.181" {
			continue
		}
		if n.Kind != "external" {
			t.Errorf("kind = %q, want external", n.Kind)
		}
		// The address belongs to the ingress node, not the client, and the label
		// has to stop it being read as the client's.
		if n.ViaNode != "cilium-w0" {
			t.Errorf("viaNode = %q, want cilium-w0", n.ViaNode)
		}
	}
}

// The kubelet checking each pod is constant and uniform, and says nothing about
// how workloads talk to each other. It is reported rather than dropped, because
// it is exactly what a whitelist ingress policy blocks — the UI decides.
func TestAKubeletProbeIsFlaggedRatherThanDropped(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{
		nodeEntry("a", "10.0.1.1", "demo", "nginx", time.Now()),
	})
	nodeIPs := k8s.NodeIPMap{IPToName: map[string]string{"10.0.1.1": "worker-1"}}

	resp := buildCiliumTopology(context.Background(), store, nil, nodeIPs, nil, false)
	e := findEdge(resp, "node:10.0.1.1", "demo/nginx")
	if e == nil {
		t.Fatal("edge missing")
	}
	// With no pod data behind it, nothing can be called a probe — the store has
	// no clients here, so the lookup finds nothing and must not guess.
	if e.HealthProbe {
		t.Error("an edge was called a probe without any pod spec to say so")
	}
}
