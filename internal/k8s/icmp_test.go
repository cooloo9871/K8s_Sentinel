package k8s

import "testing"

// The payload Cilium produced for the flow this fix exists for:
//
//	169.254.208.88 (world) -> test/helloworld-v1 to-endpoint FORWARDED
//	  (ICMPv4 DestinationUnreachable(Host))
//
// An Istio sidecar probes the cloud metadata endpoint at startup; on bare metal
// nothing answers, and the gateway on the link returns Host Unreachable. That
// error carried the gateway's address in the source field, so the graph drew an
// unknown outside address connecting to the pod — which is what an intrusion
// looks like.
const icmpUnreachableFlow = `{"flow":{"time":"2026-08-06T02:23:46.256Z","verdict":"FORWARDED",
"IP":{"source":"169.254.208.88","destination":"10.0.1.161"},
"l4":{"ICMPv4":{"type":3,"code":1}},
"source":{"labels":["reserved:world"]},
"destination":{"namespace":"test","pod_name":"helloworld-v1-66bd6799b7-jt8t8"},
"is_reply":false,"traffic_direction":"INGRESS"},"node_name":"w1"}`

func TestAnICMPErrorIsParsedAsSuch(t *testing.T) {
	flow, ok := parseCiliumFlow(icmpUnreachableFlow)
	if !ok {
		t.Fatal("the flow did not parse")
	}
	if flow.Protocol != "ICMPv4" {
		t.Errorf("protocol = %q, want ICMPv4 — an unparsed ICMP flow looks like traffic with no port", flow.Protocol)
	}
	if flow.ICMPType != 3 {
		t.Errorf("icmp type = %d, want 3 (Destination Unreachable)", flow.ICMPType)
	}
	if !flow.IsICMPError() {
		t.Error("Destination Unreachable was not recognised as an error message")
	}
}

// The buffer is what the graph is drawn from, so this is where it has to stop.
func TestAnICMPErrorDoesNotBecomeAnEdge(t *testing.T) {
	store := NewStore(nil, nil, nil, "")
	flow, _ := parseCiliumFlow(icmpUnreachableFlow)
	store.updateCiliumTopo(flow)

	if entries := store.ListCiliumTopoEntries(); len(entries) != 0 {
		t.Errorf("got %d entries, want the error report left undrawn: %+v", len(entries), entries)
	}
}

// A ping is real traffic, and a ping sweep against a pod is worth seeing. Only
// the error types are feedback about something else.
func TestAPingIsStillDrawn(t *testing.T) {
	echo := `{"flow":{"verdict":"FORWARDED",
	"IP":{"source":"10.0.1.5","destination":"10.0.1.161"},
	"l4":{"ICMPv4":{"type":8}},
	"source":{"namespace":"default","pod_name":"prober"},
	"destination":{"namespace":"test","pod_name":"helloworld-v1"},
	"is_reply":false},"node_name":"w1"}`

	flow, ok := parseCiliumFlow(echo)
	if !ok {
		t.Fatal("the flow did not parse")
	}
	if flow.IsICMPError() {
		t.Fatal("an echo request was classified as an error message")
	}
	store := NewStore(nil, nil, nil, "")
	store.updateCiliumTopo(flow)
	if len(store.ListCiliumTopoEntries()) != 1 {
		t.Error("an echo request was dropped; a ping sweep would be invisible")
	}
}

// ICMPv6 numbers its types differently — 3 is Time Exceeded there, and Echo
// Request is 128. Reusing the v4 table would drop pings and keep errors.
func TestICMPv6UsesItsOwnTypeNumbers(t *testing.T) {
	cases := []struct {
		icmpType uint32
		wantErr  bool
		what     string
	}{
		{1, true, "destination unreachable"},
		{2, true, "packet too big"},
		{3, true, "time exceeded"},
		{128, false, "echo request"},
		{129, false, "echo reply"},
	}
	for _, c := range cases {
		f := CiliumFlow{Protocol: "ICMPv6", ICMPType: c.icmpType}
		if got := f.IsICMPError(); got != c.wantErr {
			t.Errorf("ICMPv6 type %d (%s): IsICMPError = %v, want %v", c.icmpType, c.what, got, c.wantErr)
		}
	}
}

// TCP and UDP have no ICMP type; a zero value must not be read as one.
func TestTCPIsNeverAnICMPError(t *testing.T) {
	if (CiliumFlow{Protocol: "TCP"}).IsICMPError() {
		t.Error("a TCP flow was classified as an ICMP error")
	}
	if (CiliumFlow{Protocol: "UDP"}).IsICMPError() {
		t.Error("a UDP flow was classified as an ICMP error")
	}
}
