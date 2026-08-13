package handler

import (
	"context"
	"testing"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

// A link-local source used to resolve as an external node, which put the
// receiving pod into the "receiving external traffic without any declared
// exposure path" state — a security warning raised by a pod's own sidecar
// plumbing. RFC 3927 addresses are not routable beyond the local link, so one
// can never be an outside client.
func TestLinkLocalIsNotExternal(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{{
		Key: "a", SrcIP: "169.254.208.88",
		DstPod: "helloworld-v1", DstNs: "test", DstIP: "10.0.1.161",
		Verdict: "allowed", Count: 1, LastSeen: time.Now(),
	}})

	resp := buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)

	var src *TopologyNode
	for i, n := range resp.Nodes {
		if n.IP == "169.254.208.88" {
			src = &resp.Nodes[i]
		}
	}
	if src == nil {
		t.Fatal("the link-local source is missing from the graph")
	}
	if src.Kind == "external" {
		t.Error("a link-local address was classified as external, which raises a false exposure alarm")
	}
	if src.Kind != "linklocal" {
		t.Errorf("kind = %q, want linklocal", src.Kind)
	}
	// The UI keys the undeclared-exposure warning off the "ext:" prefix, so the
	// identity has to differ, not just the kind.
	if len(src.ID) >= 4 && src.ID[:4] == "ext:" {
		t.Errorf("id = %q, want an identity the external-traffic rule does not match", src.ID)
	}
}

// The metadata endpoint is the one link-local address worth naming: reaching it
// is a known credential-theft path, so it should not read as an opaque IP.
func TestCloudMetadataIsNamed(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{{
		Key: "a", SrcPod: "helloworld-v1", SrcNs: "test", SrcIP: "10.0.1.161",
		DstIP: "169.254.169.254", Port: "80",
		Verdict: "allowed", Count: 3, LastSeen: time.Now(),
	}})

	resp := buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)

	for _, n := range resp.Nodes {
		if n.IP == "169.254.169.254" {
			if n.Label != "cloud metadata" {
				t.Errorf("label = %q, want it named as the metadata service", n.Label)
			}
			return
		}
	}
	t.Fatal("the metadata endpoint is missing from the graph")
}

// A genuinely external address must still be external — the fix narrows what
// counts, it does not remove the category.
func TestARealExternalAddressIsStillExternal(t *testing.T) {
	store := k8s.NewStore(nil, nil, nil, "")
	store.SeedCiliumTopoForTest([]k8s.CiliumTopoEntry{{
		Key: "a", SrcIP: "203.0.113.9", SrcIsWorld: true,
		DstPod: "helloworld-v1", DstNs: "test", DstIP: "10.0.1.161",
		Port: "8080", Verdict: "allowed", Count: 1, LastSeen: time.Now(),
	}})

	resp := buildCiliumTopology(context.Background(), store, nil, k8s.NodeIPMap{}, nil, false)

	for _, n := range resp.Nodes {
		if n.IP == "203.0.113.9" {
			if n.Kind != "external" {
				t.Errorf("kind = %q, want external", n.Kind)
			}
			return
		}
	}
	t.Fatal("the external source is missing from the graph")
}
