package k8s

import "testing"

// A real dropped flow from a cluster running Cilium 1.18.3 with Hubble network
// policy correlation, denied by this CiliumNetworkPolicy:
//
//	spec:
//	  endpointSelector: {matchLabels: {app: traffic-generator}}
//	  enableDefaultDeny: {egress: false, ingress: false}
//	  egressDeny: [{toEndpoints: [{matchLabels: {app: echo-server}}]}]
const droppedFlowJSON = `{"flow":{"time":"2026-07-31T10:41:02.202450754Z","uuid":"cd75b2ac-8dd3-486b-beca-3d17d9d56cff","verdict":"DROPPED","drop_reason":181,"ethernet":{"source":"62:6b:d0:a4:c5:63","destination":"6e:d0:ea:78:fc:0a"},"IP":{"source":"10.0.1.235","destination":"10.0.0.21","ipVersion":"IPv4"},"l4":{"TCP":{"source_port":60524,"destination_port":80,"flags":{"SYN":true}}},"source":{"ID":423,"identity":24753,"cluster_name":"topgun","namespace":"net-lab","labels":["k8s:app=traffic-generator"],"pod_name":"traffic-generator-9b649846d-bxqfc","workloads":[{"name":"traffic-generator","kind":"Deployment"}]},"destination":{"identity":24075,"cluster_name":"topgun","namespace":"net-lab","labels":["k8s:app=echo-server"],"pod_name":"echo-server-65887564dc-jjw7k"},"Type":"L3_L4","node_name":"topgun/cilium-w1","event_type":{"type":5},"traffic_direction":"EGRESS","policy_match_type":1,"drop_reason_desc":"POLICY_DENY","Summary":"TCP Flags: SYN","egress_denied_by":[{"name":"deny-tg-to-echo","namespace":"net-lab","labels":["k8s:io.cilium.k8s.policy.name=deny-tg-to-echo"],"revision":"6","kind":"CiliumNetworkPolicy"}],"policy_log":[""]},"node_name":"topgun/cilium-w1","time":"2026-07-31T10:41:02.202450754Z"}`

func TestParseCiliumFlowPolicyDenial(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid dropped flow")
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"verdict", f.Verdict, "dropped"},
		{"srcPod", f.SrcPod, "traffic-generator-9b649846d-bxqfc"},
		{"dstPod", f.DstPod, "echo-server-65887564dc-jjw7k"},
		{"srcIP", f.SrcIP, "10.0.1.235"},
		{"dstIP", f.DstIP, "10.0.0.21"},
		{"protocol", f.Protocol, "TCP"},
		{"dropReason", f.DropReason, "POLICY_DENY"},
		// The whole point: the denying policy must be identified by name so the
		// Security Event can reference a policy that actually exists.
		{"policyName", f.PolicyName, "deny-tg-to-echo"},
		{"policyNs", f.PolicyNs, "net-lab"},
		{"direction", f.Direction, "egress"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if f.DstPort != 80 {
		t.Errorf("dstPort = %d, want 80", f.DstPort)
	}
	if f.IsReply {
		t.Error("isReply = true, want false for a SYN")
	}
	if !f.IsPolicyDenial() {
		t.Error("IsPolicyDenial() = false, want true")
	}
}

func TestSynthesizePolicyDenyEvent(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid dropped flow")
	}

	evt, ok := SynthesizePolicyDenyEvent(f)
	if !ok {
		t.Fatal("SynthesizePolicyDenyEvent dropped an attributed denial")
	}
	if evt.PolicyName != "deny-tg-to-echo" {
		t.Errorf("PolicyName = %q, want the real policy name", evt.PolicyName)
	}
	// Egress denial: the subject is the pod that was denied, not the target.
	if evt.Pod != "traffic-generator-9b649846d-bxqfc" || evt.Namespace != "net-lab" {
		t.Errorf("subject = %s/%s, want net-lab/traffic-generator-...", evt.Namespace, evt.Pod)
	}
	if evt.Function != "cilium-egress-deny" {
		t.Errorf("Function = %q, want cilium-egress-deny", evt.Function)
	}
	if evt.NetSrc != "10.0.1.235:60524" || evt.NetDest != "10.0.0.21:80" {
		t.Errorf("endpoints = %s → %s, want 10.0.1.235:60524 → 10.0.0.21:80", evt.NetSrc, evt.NetDest)
	}
	if evt.Severity() != "critical" {
		t.Errorf("Severity() = %q, want critical", evt.Severity())
	}
	if !evt.IsSecurityEvent() {
		t.Error("IsSecurityEvent() = false — the denial would never reach events, alerts or syslog")
	}
}

// An unattributed drop must produce no event at all: Security Events may never
// show a policy that does not exist, and a blank policy name is not actionable.
func TestSynthesizeSkipsUnattributedDrop(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid dropped flow")
	}
	f.PolicyName = "" // as Hubble reports it for a default-deny drop
	if _, ok := SynthesizePolicyDenyEvent(f); ok {
		t.Error("SynthesizePolicyDenyEvent emitted an event with no policy name")
	}
}
