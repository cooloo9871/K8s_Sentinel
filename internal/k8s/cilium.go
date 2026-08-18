package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	observer "github.com/cilium/cilium/api/v1/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CiliumFlow is a normalized Hubble/Cilium network flow.
type CiliumFlow struct {
	Time    string `json:"time"`
	Verdict string `json:"verdict"` // FORWARDED | DROPPED | AUDIT
	// Source endpoint
	SrcIP   string `json:"srcIP"`
	SrcPort uint32 `json:"srcPort"`
	SrcPod  string `json:"srcPod"`
	SrcNs   string `json:"srcNs"`
	// Destination endpoint
	DstIP   string `json:"dstIP"`
	DstPort uint32 `json:"dstPort"`
	DstPod  string `json:"dstPod"`
	DstNs   string `json:"dstNs"`
	// Transport
	Protocol string `json:"protocol"` // TCP | UDP | ICMPv4 | ICMPv6
	// ICMP message type, meaningful only for the ICMP protocols. Kept because the
	// type is the whole difference between a probe and an error report.
	ICMPType uint32 `json:"icmpType,omitempty"`
	// L7 (only when Cilium proxy is active)
	L7Type     string `json:"l7Type,omitempty"` // HTTP | gRPC | DNS | kafka
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPURL    string `json:"httpURL,omitempty"`
	HTTPStatus uint32 `json:"httpStatus,omitempty"`
	DNSQuery   string `json:"dnsQuery,omitempty"`
	DNSRcode   string `json:"dnsRcode,omitempty"`
	// Drop details (only meaningful when Verdict == "dropped")
	DropReason string `json:"dropReason,omitempty"`
	// Policy that denied the traffic — requires Hubble network policy
	// correlation (hubble-network-policy-correlation-enabled), otherwise empty.
	PolicyName string `json:"policyName,omitempty"`
	PolicyNs   string `json:"policyNs,omitempty"`
	Direction  string `json:"direction,omitempty"` // "ingress" | "egress", from Hubble's traffic_direction
	// Metadata
	NodeName string `json:"nodeName"`
	IsReply  bool   `json:"isReply"`
	// Whether Cilium identified the source as outside the cluster. Kept because
	// the address cannot be trusted to say so: inbound NodePort traffic forwarded
	// across nodes is SNATed to the ingress node's cilium_host, so the IP looks
	// in-cluster while the identity still reads reserved:world.
	SrcIsWorld bool `json:"srcIsWorld"`
}

// IsPolicyDenial reports whether this flow was dropped by a network policy, as
// opposed to the many non-security drop reasons Cilium also reports (stale or
// unroutable IP, unsupported L3 protocol, …). Only policy denials belong in the
// security event stream — treating every drop as an incident would flood it.
func (f CiliumFlow) IsPolicyDenial() bool {
	if f.Verdict != "dropped" {
		return false
	}
	if f.PolicyName != "" {
		return true // policy correlation identified the rule
	}
	// An L7 drop is always a policy decision: the Envoy proxy only rejects a
	// request because a rule said so. drop_reason_desc describes datapath
	// drops and is not reliably set for proxy rejections, so keying on it
	// alone would silently lose the denials that matter most — an unauthorised
	// method or path reaching a service.
	if f.L7Type != "" {
		return true
	}
	return strings.Contains(strings.ToUpper(f.DropReason), "POLICY")
}

// IsICMPError reports whether the flow is an ICMP error message rather than a
// probe: Destination Unreachable, Time Exceeded, Redirect and their kin.
//
// These are the network reporting back about a packet that was already sent, and
// the reporter's address sits in the source field — so drawing one as an edge
// states the opposite of what happened. A pod whose metadata lookup went nowhere
// appeared to be *receiving* traffic from an unknown address, which is exactly
// the shape of an intrusion.
//
// Echo request and reply are deliberately not included. A ping is real traffic
// and a ping sweep is worth seeing.
func (f CiliumFlow) IsICMPError() bool {
	switch f.Protocol {
	case "ICMPv4":
		// 3 unreachable · 4 source quench · 5 redirect · 11 time exceeded ·
		// 12 parameter problem
		switch f.ICMPType {
		case 3, 4, 5, 11, 12:
			return true
		}
	case "ICMPv6":
		// 1 unreachable · 2 packet too big · 3 time exceeded · 4 parameter problem
		switch f.ICMPType {
		case 1, 2, 3, 4:
			return true
		}
	}
	return false
}

// ciliumNamespaces lists where to look for Cilium, in order. An explicit
// CILIUM_NAMESPACE is taken as the only answer; otherwise the three places the
// chart is commonly installed are all searched.
//
// Detection used to search all three while every exec afterwards targeted the
// configured default alone, so a cluster running Cilium anywhere but kube-system
// logged "Cilium detected, starting flow stream" and then failed to find an agent
// pod every 15 seconds, forever, with an empty topology and no explanation.
func ciliumNamespaces() []string {
	if ns := os.Getenv("CILIUM_NAMESPACE"); ns != "" {
		return []string{ns}
	}
	return []string{"kube-system", "cilium", "cilium-system"}
}

// ciliumNamespace returns the namespace the Cilium DaemonSet is in, and whether
// it was found. One scan, so callers that need both "is Cilium here" and "where
// is Relay" do not probe the same namespaces twice.
func (s *Store) ciliumNamespace(ctx context.Context) (string, bool) {
	if s.typed == nil {
		return "", false
	}
	for _, ns := range ciliumNamespaces() {
		if _, err := s.typed.AppsV1().DaemonSets(ns).Get(ctx, "cilium", metav1.GetOptions{}); err == nil {
			return ns, true
		}
	}
	return "", false
}

// DetectCilium returns true when a Cilium DaemonSet is present in the cluster.
func (s *Store) DetectCilium(ctx context.Context) bool {
	_, ok := s.ciliumNamespace(ctx)
	return ok
}

// relayAddressIn is the relay endpoint for a given Cilium namespace.
func relayAddressIn(ns string) string {
	return "hubble-relay." + ns + ".svc.cluster.local:80"
}

// hubbleRelayAddress is where Hubble Relay serves the aggregated Observer API.
// Relay collects from every node, so unlike the Tetragon agents there is one
// endpoint rather than a per-pod fan-out. HUBBLE_RELAY_ADDRESS overrides it;
// otherwise the relay Service in the namespace Cilium was found in. The env is
// read first so the namespace scan is skipped when the address is pinned.
func (s *Store) hubbleRelayAddress(ctx context.Context) string {
	if a := os.Getenv("HUBBLE_RELAY_ADDRESS"); a != "" {
		return a
	}
	ns, ok := s.ciliumNamespace(ctx)
	if !ok {
		ns = "kube-system"
	}
	return relayAddressIn(ns)
}

// StreamCiliumFlows streams every node's Hubble flows from Hubble Relay. It
// returns when the stream exits (error or context done).
func (s *Store) StreamCiliumFlows(ctx context.Context, out chan<- CiliumFlow) error {
	conn, err := dialGRPC("HUBBLE_RELAY", s.hubbleRelayAddress(ctx))
	if err != nil {
		return fmt.Errorf("dial hubble-relay: %w", err)
	}
	defer conn.Close()

	// follow keeps the stream open; number 0 means unbounded here.
	stream, err := observer.NewObserverClient(conn).GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		return fmt.Errorf("GetFlows: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv flow: %w", err)
		}
		if resp.GetFlow() == nil {
			continue // node-status and lost-events messages carry no flow
		}
		// Bridged through the same parser the CLI JSON used, by marshaling the
		// response exactly as `hubble observe -o json` does.
		line, err := marshalJSON(resp)
		if err != nil {
			continue
		}
		flow, ok := parseCiliumFlow(line)
		if !ok {
			continue
		}
		select {
		case out <- flow:
		case <-ctx.Done():
			return nil
		}
	}
}

// ciliumPolicyRef is one entry of Hubble's *_denied_by / *_allowed_by policy
// correlation lists.
type ciliumPolicyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
}

// parseCiliumFlow parses one NDJSON line from `hubble observe -o json`.
func parseCiliumFlow(line string) (CiliumFlow, bool) {
	// Hubble JSON envelope: {"flow": {...}, "node_name": "...", "time": "..."}
	// Hubble serialises the IP field as "IP" (uppercase) in some versions
	// and "ip" (lowercase) in others depending on the protobuf JSON marshaler.
	// We decode the raw envelope first, then handle both cases.
	var env struct {
		NodeName string `json:"node_name"`
		Time     string `json:"time"`
		Flow     struct {
			Time    string `json:"time"`
			Verdict string `json:"verdict"`
			IsReply *bool  `json:"is_reply"`
			Type    string `json:"Type"` // "L3_L4" | "L7"
			Source  struct {
				Namespace string   `json:"namespace"`
				PodName   string   `json:"pod_name"`
				Labels    []string `json:"labels"`
			} `json:"source"`
			Destination struct {
				Namespace string `json:"namespace"`
				PodName   string `json:"pod_name"`
			} `json:"destination"`
			IP struct {
				Source      string `json:"source"`
				Destination string `json:"destination"`
			} `json:"IP"`
			IPLower struct {
				Source      string `json:"source"`
				Destination string `json:"destination"`
			} `json:"ip"`
			L4 struct {
				TCP *struct {
					SrcPort uint32 `json:"source_port"`
					DstPort uint32 `json:"destination_port"`
				} `json:"TCP"`
				UDP *struct {
					SrcPort uint32 `json:"source_port"`
					DstPort uint32 `json:"destination_port"`
				} `json:"UDP"`
				ICMPv4 *struct {
					Type uint32 `json:"type"`
				} `json:"ICMPv4"`
				ICMPv6 *struct {
					Type uint32 `json:"type"`
				} `json:"ICMPv6"`
			} `json:"l4"`
			DropReasonDesc   string `json:"drop_reason_desc"`
			TrafficDirection string `json:"traffic_direction"` // "INGRESS" | "EGRESS"
			// Populated when Hubble network policy correlation is enabled
			EgressDeniedBy  []ciliumPolicyRef `json:"egress_denied_by"`
			IngressDeniedBy []ciliumPolicyRef `json:"ingress_denied_by"`
			L7              *struct {
				Type string `json:"type"` // REQUEST | RESPONSE
				HTTP *struct {
					Method   string `json:"method"`
					URL      string `json:"url"`
					Code     uint32 `json:"code"`
					Protocol string `json:"protocol"`
				} `json:"http"`
				DNS *struct {
					Query  string   `json:"query"`
					Rcode  string   `json:"rcode"`
					QTypes []string `json:"qtypes"`
				} `json:"dns"`
				Grpc *struct {
					Method string `json:"method"`
				} `json:"grpc"`
			} `json:"l7"`
			NodeName string `json:"node_name"`
		} `json:"flow"`
	}
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		return CiliumFlow{}, false
	}
	f := env.Flow
	if f.Verdict == "" && f.IP.Source == "" && f.IPLower.Source == "" {
		return CiliumFlow{}, false
	}

	// Use whichever IP field is populated (Hubble uses "IP" or "ip" depending on version).
	// Strip IPv4-mapped IPv6 prefix "::ffff:" so IPs match the plain IPv4 keys in ipMap.
	stripIPv4Mapped := func(ip string) string {
		if strings.HasPrefix(ip, "::ffff:") {
			return ip[7:]
		}
		return ip
	}
	srcIP := stripIPv4Mapped(f.IP.Source)
	if srcIP == "" {
		srcIP = stripIPv4Mapped(f.IPLower.Source)
	}
	dstIP := stripIPv4Mapped(f.IP.Destination)
	if dstIP == "" {
		dstIP = stripIPv4Mapped(f.IPLower.Destination)
	}

	flow := CiliumFlow{
		Time:     f.Time,
		Verdict:  verdictLabel(f.Verdict),
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPod:   f.Source.PodName,
		SrcNs:    f.Source.Namespace,
		DstPod:   f.Destination.PodName,
		DstNs:    f.Destination.Namespace,
		NodeName: f.NodeName,
	}
	if flow.NodeName == "" {
		flow.NodeName = env.NodeName
	}
	flow.NodeName = bareNodeName(flow.NodeName)
	if flow.Time == "" {
		flow.Time = env.Time
	}
	if f.IsReply != nil {
		flow.IsReply = *f.IsReply
	}
	for _, l := range f.Source.Labels {
		if l == "reserved:world" {
			flow.SrcIsWorld = true
			break
		}
	}

	// Drop details and policy correlation
	flow.DropReason = f.DropReasonDesc
	flow.Direction = strings.ToLower(f.TrafficDirection)
	if len(f.EgressDeniedBy) > 0 {
		flow.Direction = "egress"
		flow.PolicyName = f.EgressDeniedBy[0].Name
		flow.PolicyNs = f.EgressDeniedBy[0].Namespace
	} else if len(f.IngressDeniedBy) > 0 {
		flow.Direction = "ingress"
		flow.PolicyName = f.IngressDeniedBy[0].Name
		flow.PolicyNs = f.IngressDeniedBy[0].Namespace
	}

	// Transport layer
	if f.L4.TCP != nil {
		flow.Protocol = "TCP"
		flow.SrcPort = f.L4.TCP.SrcPort
		flow.DstPort = f.L4.TCP.DstPort
	} else if f.L4.UDP != nil {
		flow.Protocol = "UDP"
		flow.SrcPort = f.L4.UDP.SrcPort
		flow.DstPort = f.L4.UDP.DstPort
	} else if f.L4.ICMPv4 != nil {
		flow.Protocol = "ICMPv4"
		flow.ICMPType = f.L4.ICMPv4.Type
	} else if f.L4.ICMPv6 != nil {
		flow.Protocol = "ICMPv6"
		flow.ICMPType = f.L4.ICMPv6.Type
	}

	// L7 application layer
	if f.L7 != nil {
		if f.L7.HTTP != nil {
			flow.L7Type = "HTTP"
			flow.HTTPMethod = f.L7.HTTP.Method
			flow.HTTPURL = f.L7.HTTP.URL
			if f.L7.Type == "RESPONSE" {
				flow.HTTPStatus = f.L7.HTTP.Code
			}
		} else if f.L7.DNS != nil {
			flow.L7Type = "DNS"
			flow.DNSQuery = f.L7.DNS.Query
			flow.DNSRcode = f.L7.DNS.Rcode
		} else if f.L7.Grpc != nil {
			flow.L7Type = "gRPC"
			flow.HTTPURL = f.L7.Grpc.Method
		}
	}

	return flow, true
}

// bareNodeName drops the cluster qualifier Hubble puts in front of the node.
//
// Hubble reports node_name as "cluster-name/node-name", so a Security Event from
// a network rule named its node "default/w1" while a Tetragon event on the same
// node named it "w1". One cluster is all this console looks at, so the qualifier
// says nothing and only made the two disagree.
func bareNodeName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func verdictLabel(v string) string {
	switch v {
	case "FORWARDED":
		return "allowed"
	case "DROPPED":
		return "dropped"
	case "AUDIT":
		return "audit"
	default:
		return v
	}
}

// HubbleStatus reports whether Hubble Relay's Observer API is reachable.
type HubbleStatus struct {
	Available bool   `json:"available"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message,omitempty"`
}

// CheckHubbleReady asks Hubble Relay for its status. Available reports that
// Cilium is present at all; Ready reports that the flow source Network Topology
// depends on is answering.
func (s *Store) CheckHubbleReady(ctx context.Context) HubbleStatus {
	ns, ok := s.ciliumNamespace(ctx)
	if !ok {
		return HubbleStatus{Available: false, Message: "Cilium not detected"}
	}
	addr := os.Getenv("HUBBLE_RELAY_ADDRESS")
	if addr == "" {
		addr = relayAddressIn(ns)
	}
	conn, err := dialGRPC("HUBBLE_RELAY", addr)
	if err != nil {
		return HubbleStatus{Available: true, Ready: false, Message: "dial hubble-relay: " + err.Error()}
	}
	defer conn.Close()

	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := observer.NewObserverClient(conn).ServerStatus(statusCtx, &observer.ServerStatusRequest{}); err != nil {
		return HubbleStatus{Available: true, Ready: false, Message: "hubble-relay not answering: " + err.Error()}
	}
	return HubbleStatus{Available: true, Ready: true}
}

// ── Cilium Topology Buffer ──────────────────────────────────────────────────

// CiliumTopoEntry tracks a unique directed connection seen in Cilium flows,
// keyed by (srcID, dstID, port). Accumulates count and L7 info.
type CiliumTopoEntry struct {
	Key           string // its key in the buffer, so stale entries can be evicted
	SrcID, DstID  string
	SrcPod, SrcNs string
	DstPod, DstNs string
	SrcIP, DstIP  string
	// Cilium identified the source as outside the cluster, whatever the address
	// says — see CiliumFlow.SrcIsWorld.
	SrcIsWorld bool
	Port       string
	Protocol   string
	Verdict    string // "allowed" | "dropped"
	// Set for denials: the policy Hubble named, and the direction the rule
	// applies to. Empty PolicyName means default-deny, resolved at read time.
	PolicyName string
	Direction  string
	L7Type     string
	HTTPMethod string
	HTTPURL    string
	HTTPStatus uint32
	DNSQuery   string
	Count      int
	LastSeen   time.Time
}

// SynthesizePolicyDenyEvent converts a Cilium network policy denial into a
// security event so it flows through the same retention, alerting and syslog
// pipeline as Tetragon events, rather than being visible only as a red edge in
// the topology graph.
//
// It emits an event only when Hubble names the policy that denied the traffic.
// An unattributed drop is not recorded: the Policy column must only ever show
// policies that exist in the cluster, and a row naming no policy — or a
// fabricated one — tells the operator nothing actionable. Attribution requires
// Hubble network policy correlation
// (--set hubble.enabled=true --set hubble.metrics.enableNetworkPolicyCorrelation,
// or hubble-network-policy-correlation-enabled=true in cilium-config) and, for
// L3/L4, an explicit ingressDeny/egressDeny rule — a default-deny drop has no
// rule to attribute, because it is the absence of an allow rule.
func (s *Store) SynthesizePolicyDenyEvent(ctx context.Context, f CiliumFlow) (TetragonEvent, bool) {
	if !f.IsPolicyDenial() {
		return TetragonEvent{}, false
	}
	// A reply carries the endpoints the other way round, so naming its source as
	// the actor would report the wrong workload and the wrong direction. Only
	// the request side defines who attempted what — the same reason the topology
	// buffer drops replies.
	if f.IsReply {
		return TetragonEvent{}, false
	}

	// The subject is the workload that attempted the connection, matching every
	// other rule type: a process or file event names the pod that acted, so a
	// network event should too. Only when the source is not a pod — an external
	// client denied on ingress — does it fall back to the pod being protected,
	// since an event naming no pod at all would be useless.
	ns, pod := f.SrcNs, f.SrcPod
	if pod == "" {
		ns, pod = f.DstNs, f.DstPod
	}
	if pod == "" {
		return TetragonEvent{}, false // no workload to attribute the denial to
	}

	// Hubble names the policy only for explicit ingressDeny/egressDeny rules.
	// An allowlist policy denies by default-deny — the absence of an allow rule —
	// so fall back to asking which of the user's policies govern this pod in
	// this direction. Still no answer means no event: better silent than naming
	// a policy that does not exist.
	policyName := f.PolicyName
	if policyName == "" {
		// Attribution looks at the pod the policy governs, which for an ingress
		// denial is the destination — not necessarily the subject above.
		ownerNs, ownerPod := f.SrcNs, f.SrcPod
		if f.Direction == "ingress" {
			ownerNs, ownerPod = f.DstNs, f.DstPod
		}
		policyName = s.AttributePolicyDenial(ctx, ownerNs, ownerPod, f.Direction)
	}
	if policyName == "" {
		return TetragonEvent{}, false
	}

	function := "cilium-policy-deny"
	if f.Direction != "" {
		function = "cilium-" + f.Direction + "-deny"
	}

	src, dst := f.SrcIP, f.DstIP
	if f.SrcPort > 0 {
		src = fmt.Sprintf("%s:%d", src, f.SrcPort)
	}
	if f.DstPort > 0 {
		dst = fmt.Sprintf("%s:%d", dst, f.DstPort)
	}

	// For an L7 rejection, the request that was refused is the actionable
	// detail: "denied" is far less useful than "denied POST /admin".
	dropReason := f.DropReason
	if f.L7Type != "" {
		detail := f.L7Type
		if f.HTTPMethod != "" || f.HTTPURL != "" {
			detail = strings.TrimSpace(f.L7Type + " " + f.HTTPMethod + " " + f.HTTPURL)
		} else if f.DNSQuery != "" {
			detail = f.L7Type + " " + f.DNSQuery
		}
		if dropReason == "" {
			dropReason = detail + " denied by policy"
		} else {
			dropReason = dropReason + " (" + detail + ")"
		}
	}

	return TetragonEvent{
		Type:       "policy-deny",
		Source:     "cilium",
		Time:       f.Time,
		NodeName:   f.NodeName,
		Namespace:  ns,
		Pod:        pod,
		Container:  s.PodContainer(ctx, ns, pod),
		Action:     "deny",
		PolicyName: policyName,
		Function:   function,
		NetSrc:     src,
		NetDest:    dst,
		DropReason: dropReason,
	}, true
}
