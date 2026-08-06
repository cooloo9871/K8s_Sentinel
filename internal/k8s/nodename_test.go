package k8s

import "testing"

// Hubble reports node_name as "cluster-name/node-name". A Security Event from a
// network rule therefore named its node "default/w1", while a Tetragon event on
// the very same node named it "w1" — one console, one cluster, two answers.
func TestTheClusterQualifierIsStrippedFromTheNodeName(t *testing.T) {
	flow, ok := parseCiliumFlow(`{"flow":{"verdict":"DROPPED",
	"IP":{"source":"10.0.1.5","destination":"10.0.1.161"},
	"l4":{"TCP":{"source_port":40000,"destination_port":80}},
	"source":{"namespace":"test","pod_name":"client"},
	"destination":{"namespace":"test","pod_name":"server"},
	"node_name":"default/w1","is_reply":false}}`)
	if !ok {
		t.Fatal("the flow did not parse")
	}
	if flow.NodeName != "w1" {
		t.Errorf("nodeName = %q, want the bare node name", flow.NodeName)
	}
}

// The envelope carries it too, on the versions that leave it out of the flow.
func TestTheQualifierIsStrippedFromTheEnvelopeToo(t *testing.T) {
	flow, ok := parseCiliumFlow(`{"node_name":"my-cluster/worker-2","flow":{"verdict":"FORWARDED",
	"IP":{"source":"10.0.1.5","destination":"10.0.1.161"},
	"l4":{"TCP":{"destination_port":80}},
	"source":{"namespace":"test","pod_name":"client"},
	"destination":{"namespace":"test","pod_name":"server"}}}`)
	if !ok {
		t.Fatal("the flow did not parse")
	}
	if flow.NodeName != "worker-2" {
		t.Errorf("nodeName = %q, want the bare node name", flow.NodeName)
	}
}

func TestBareNodeName(t *testing.T) {
	cases := map[string]string{
		"default/w1":         "w1",
		"my-cluster/worker2": "worker2",
		// Already bare — Tetragon reports it this way, and so do some Hubble
		// versions.
		"w1": "w1",
		"":   "",
		// A node name is a DNS subdomain and cannot contain a slash, so the last
		// segment is always the node.
		"a/b/node-3": "node-3",
	}
	for in, want := range cases {
		if got := bareNodeName(in); got != want {
			t.Errorf("bareNodeName(%q) = %q, want %q", in, got, want)
		}
	}
}
