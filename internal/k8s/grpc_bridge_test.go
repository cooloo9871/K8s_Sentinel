package k8s

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observer "github.com/cilium/cilium/api/v1/observer"
	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The gRPC ingestion bridges protobuf back to the NDJSON parsers by marshaling
// each message with the proto field names — exactly what `tetra getevents -o
// json` and `hubble observe -o json` do. These tests pin that contract with
// real protobuf messages: if a future proto or marshaler change stops
// reproducing the CLI shape the parsers were built for, they fail here rather
// than silently in a cluster.

func TestTetragonGRPCBridgesToTheParser(t *testing.T) {
	resp := &tetragon.GetEventsResponse{
		NodeName: "cluster/node-1",
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "demo", Name: "web-1",
						Container: &tetragon.Container{Name: "app"},
					},
				},
				FunctionName: "tcp_connect",
				PolicyName:   "net-watch",
				Action:       tetragon.KprobeAction_KPROBE_ACTION_SIGKILL,
			},
		},
	}
	line, err := marshalJSON(resp)
	if err != nil {
		t.Fatal(err)
	}
	evt, ok := parseTetragonLog(line)
	if !ok {
		t.Fatal("the marshaled kprobe did not parse")
	}
	if evt.Type != "kprobe" || evt.Function != "tcp_connect" || evt.PolicyName != "net-watch" {
		t.Errorf("type/function/policy = %q/%q/%q", evt.Type, evt.Function, evt.PolicyName)
	}
	if evt.Pod != "web-1" || evt.Namespace != "demo" || evt.Container != "app" {
		t.Errorf("pod context = %q/%q/%q", evt.Namespace, evt.Pod, evt.Container)
	}
	// SIGKILL is an enforced block, so the whole severity pipeline keys on it.
	if evt.Action != "kill" || !evt.Blocked() || evt.Severity() != "critical" {
		t.Errorf("action/blocked/severity = %q/%v/%q", evt.Action, evt.Blocked(), evt.Severity())
	}
	if !evt.IsSecurityEvent() {
		t.Error("a policy-named kprobe is not a security event")
	}
}

// The process-cache seed has its own bridge: a ProcessInternal from GetDebug
// marshaled to the shape parseAndSeedProcessCache reads. Untested, a proto
// field rename would make every seed silently drop (count 0, nil error).
func TestProcessCacheGRPCBridgesToTheSeeder(t *testing.T) {
	s := NewStore(nil, nil, nil, "")
	pi := &tetragon.ProcessInternal{Process: &tetragon.Process{
		Binary: "/usr/sbin/nginx",
		Pod:    &tetragon.Pod{Namespace: "demo", Name: "web-1"},
	}}
	line, err := marshalJSON(pi)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.parseAndSeedProcessCache([]byte(line))
	if err != nil || n != 1 {
		t.Fatalf("seeded %d (err %v), want 1", n, err)
	}
	profiles := s.Discovery.All()
	if len(profiles) != 1 || profiles[0].Namespace != "demo" || profiles[0].Pod != "web-1" {
		t.Errorf("discovery profiles = %+v, want one for demo/web-1", profiles)
	}
}

func TestHubbleGRPCBridgesToTheParser(t *testing.T) {
	resp := &observer.GetFlowsResponse{
		NodeName: "node-1",
		ResponseTypes: &observer.GetFlowsResponse_Flow{
			Flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				NodeName:         "cluster/node-1",
				IsReply:          wrapperspb.Bool(false),
				Source:           &flowpb.Endpoint{Namespace: "demo", PodName: "client-1", Labels: []string{"reserved:world"}},
				Destination:      &flowpb.Endpoint{Namespace: "demo", PodName: "server-1"},
				IP:               &flowpb.IP{Source: "10.0.0.1", Destination: "10.0.0.2"},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 45000, DestinationPort: 80}}},
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		},
	}
	line, err := marshalJSON(resp)
	if err != nil {
		t.Fatal(err)
	}
	flow, ok := parseCiliumFlow(line)
	if !ok {
		t.Fatal("the marshaled flow did not parse")
	}
	if flow.Verdict != "dropped" || flow.Protocol != "TCP" || flow.DstPort != 80 {
		t.Errorf("verdict/proto/dport = %q/%q/%d", flow.Verdict, flow.Protocol, flow.DstPort)
	}
	if flow.SrcPod != "client-1" || flow.DstPod != "server-1" || flow.Direction != "egress" {
		t.Errorf("src/dst/dir = %q/%q/%q", flow.SrcPod, flow.DstPod, flow.Direction)
	}
	// Identity outranks address: reserved:world in the labels marks the source
	// as external even though its IP looks in-cluster.
	if !flow.SrcIsWorld {
		t.Error("reserved:world label did not set SrcIsWorld")
	}
	// The node qualifier is dropped so network and Tetragon events agree.
	if flow.NodeName != "node-1" {
		t.Errorf("nodeName = %q, want the bare name", flow.NodeName)
	}
}
