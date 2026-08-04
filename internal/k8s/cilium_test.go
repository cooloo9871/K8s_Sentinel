package k8s

import (
	"context"
	"testing"
)

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

	var s Store // no clients: Hubble already named the policy, no lookup needed
	evt, ok := s.SynthesizePolicyDenyEvent(context.Background(), f)
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
	// No Kubernetes clients, so self-attribution finds nothing either.
	var s Store
	if _, ok := s.SynthesizePolicyDenyEvent(context.Background(), f); ok {
		t.Error("SynthesizePolicyDenyEvent emitted an event with no policy name")
	}
}

// An L7 rejection is dropped by the Envoy proxy, not the datapath, so it can
// arrive with no drop_reason_desc and no policy correlation. It must still be
// recorded — an unauthorised method or path reaching a service is exactly the
// denial worth alerting on. Models a request refused by:
//
//	ingress: [{fromEndpoints: [{matchLabels: {env: prod}}],
//	           toPorts: [{ports: [{port: "8080"}], rules: {http: [{method: GET, path: /hostname}]}}]}]
const l7DeniedFlowJSON = `{"flow":{"time":"2026-08-03T06:00:00Z","verdict":"DROPPED","IP":{"source":"10.0.1.50","destination":"10.0.2.60","ipVersion":"IPv4"},"l4":{"TCP":{"source_port":45000,"destination_port":8080}},"source":{"namespace":"demo","pod_name":"client-prod-1"},"destination":{"namespace":"demo","pod_name":"service-abc"},"Type":"L7","node_name":"topgun/cilium-w1","traffic_direction":"INGRESS","l7":{"type":"REQUEST","http":{"method":"POST","url":"/admin","protocol":"HTTP/1.1"}}},"node_name":"topgun/cilium-w1","time":"2026-08-03T06:00:00Z"}`

func TestL7DenialIsRecordedWithoutDropReason(t *testing.T) {
	f, ok := parseCiliumFlow(l7DeniedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid L7 flow")
	}
	if f.DropReason != "" {
		t.Fatalf("test premise broken: expected no drop_reason_desc, got %q", f.DropReason)
	}
	if f.L7Type != "HTTP" || f.HTTPMethod != "POST" || f.HTTPURL != "/admin" {
		t.Fatalf("L7 not parsed: %s %s %s", f.L7Type, f.HTTPMethod, f.HTTPURL)
	}
	// Without the L7 branch this returns false and the denial is silently lost.
	if !f.IsPolicyDenial() {
		t.Error("IsPolicyDenial() = false for an L7 drop")
	}
	if f.Direction != "ingress" {
		t.Errorf("Direction = %q, want ingress from traffic_direction", f.Direction)
	}
}

func TestL7DenialEventNamesTheRefusedRequest(t *testing.T) {
	f, _ := parseCiliumFlow(l7DeniedFlowJSON)
	// Hubble did not correlate a policy; stand in for what attribution resolves.
	f.PolicyName = "l7-rule"

	var s Store
	evt, ok := s.SynthesizePolicyDenyEvent(context.Background(), f)
	if !ok {
		t.Fatal("L7 denial produced no event")
	}
	// The subject is the workload that made the request, consistent with every
	// other rule type — not the pod being protected.
	if evt.Pod != "client-prod-1" || evt.Namespace != "demo" {
		t.Errorf("subject = %s/%s, want demo/client-prod-1", evt.Namespace, evt.Pod)
	}
	if evt.Function != "cilium-ingress-deny" {
		t.Errorf("Function = %q, want cilium-ingress-deny", evt.Function)
	}
	// "denied" alone is not actionable; the refused request must be visible.
	if evt.DropReason != "HTTP POST /admin denied by policy" {
		t.Errorf("DropReason = %q, want the refused request", evt.DropReason)
	}
}

// An external client denied on ingress has no source pod, so the event falls
// back to the pod being protected rather than being dropped for having no
// workload at all.
func TestIngressDenialFromOutsideFallsBackToTarget(t *testing.T) {
	f, ok := parseCiliumFlow(l7DeniedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid flow")
	}
	f.SrcPod, f.SrcNs = "", "" // denied client is outside the cluster
	f.PolicyName = "l7-rule"

	var s Store
	evt, ok := s.SynthesizePolicyDenyEvent(context.Background(), f)
	if !ok {
		t.Fatal("external ingress denial produced no event")
	}
	if evt.Pod != "service-abc" || evt.Namespace != "demo" {
		t.Errorf("subject = %s/%s, want the protected pod demo/service-abc", evt.Namespace, evt.Pod)
	}
}

// A reply carries source and destination the other way round, so synthesizing an
// event from one would name the wrong workload as the actor.
func TestReplyFlowProducesNoDenialEvent(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid flow")
	}
	f.IsReply = true

	var s Store
	if _, ok := s.SynthesizePolicyDenyEvent(context.Background(), f); ok {
		t.Error("reply flow produced a denial event")
	}
}

// Inbound NodePort traffic forwarded across nodes arrives SNATed to the ingress
// node's cilium_host, so the address reads as in-cluster while Cilium still
// knows the source is outside. Losing that identity is what made external
// traffic look like a node talking to a pod.
func TestReservedWorldSourceIsRecognisedDespiteAnInClusterAddress(t *testing.T) {
	line := `{"flow":{"time":"2026-08-04T15:00:00Z","verdict":"FORWARDED",` +
		`"IP":{"source":"10.0.0.181","destination":"10.0.1.181","ipVersion":"IPv4"},` +
		`"l4":{"TCP":{"source_port":41000,"destination_port":80}},` +
		`"source":{"identity":2,"labels":["reserved:world"]},` +
		`"destination":{"namespace":"default","pod_name":"nginx"},` +
		`"traffic_direction":"INGRESS"},"node_name":"topgun/cilium-w1"}`

	f, ok := parseCiliumFlow(line)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid flow")
	}
	if !f.SrcIsWorld {
		t.Error("reserved:world source was not recognised")
	}
	if f.SrcIP != "10.0.0.181" {
		t.Errorf("SrcIP = %q, want the post-SNAT address as reported", f.SrcIP)
	}
}

func TestPodSourceIsNotWorld(t *testing.T) {
	f, ok := parseCiliumFlow(droppedFlowJSON)
	if !ok {
		t.Fatal("parseCiliumFlow rejected a valid flow")
	}
	if f.SrcIsWorld {
		t.Error("a pod source was labelled as outside the cluster")
	}
}
