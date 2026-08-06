package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
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

// ciliumNamespaces lists where to look for Cilium, in order. An explicit
// CILIUM_NAMESPACE is taken as the only answer; otherwise the three places the
// chart is commonly installed are all searched.
//
// Detection used to search all three while every exec afterwards targeted the
// configured default alone, so a cluster running Cilium anywhere but kube-system
// logged "Cilium detected, starting flow stream" and then failed to find an agent
// pod every 15 seconds, forever, with an empty topology and no explanation.
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

func ciliumNamespaces() []string {
	if ns := os.Getenv("CILIUM_NAMESPACE"); ns != "" {
		return []string{ns}
	}
	return []string{"kube-system", "cilium", "cilium-system"}
}

// DetectCilium returns true when a Cilium DaemonSet is present in the cluster.
func (s *Store) DetectCilium(ctx context.Context) bool {
	if s.typed == nil {
		return false
	}
	for _, ns := range ciliumNamespaces() {
		if _, err := s.typed.AppsV1().DaemonSets(ns).Get(ctx, "cilium", metav1.GetOptions{}); err == nil {
			return true
		}
	}
	return false
}

// StreamCiliumFlows streams Hubble flows from all Cilium agent pods concurrently.
// It returns when all pod streams exit (error or context done).
func (s *Store) StreamCiliumFlows(ctx context.Context, out chan<- CiliumFlow) error {
	ns, pods, err := s.findAllCiliumPods(ctx)
	if err != nil {
		return fmt.Errorf("no Cilium agent pods found: %w", err)
	}
	var wg sync.WaitGroup
	for _, pod := range pods {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := s.streamCiliumFromPod(ctx, ns, name, out); err != nil && ctx.Err() == nil {
				log.Printf("cilium-stream: pod %s: %v", name, err)
			}
		}(pod)
	}
	wg.Wait()
	return nil
}

func (s *Store) streamCiliumFromPod(ctx context.Context, namespace, podName string, out chan<- CiliumFlow) error {
	req := s.typed.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "cilium-agent",
			Command:   []string{"hubble", "observe", "--follow", "-o", "json", "--all-namespaces"},
			Stdout:    true,
			Stderr:    false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("exec %s: %w", podName, err)
	}

	pr, pw := io.Pipe()
	// Closing the reader makes any further write fail with ErrClosedPipe, which
	// unblocks the exec goroutine. Without it, leaving this loop early — a
	// scanner error, most plausibly a line over the buffer size — left exec
	// blocked writing into a pipe nobody reads, so `<-execDone` never returned.
	// That wedged this pod's stream, hence StreamCiliumFlows' WaitGroup, hence
	// the reconnect loop: flow collection stopped cluster-wide until a restart.
	defer pr.Close()
	execDone := make(chan error, 1)
	go func() {
		execDone <- exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: pw,
		})
		pw.Close()
	}()

	scanner := bufio.NewScanner(pr)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
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
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read flows from %s: %w", podName, err)
	}
	return <-execDone
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

// findAllCiliumPods returns the namespace Cilium was found in and its running
// agent pods. The namespace is returned rather than assumed, so every exec that
// follows goes where the pods actually are.
func (s *Store) findAllCiliumPods(ctx context.Context) (string, []string, error) {
	for _, ns := range ciliumNamespaces() {
		for _, sel := range []string{"k8s-app=cilium", "app.kubernetes.io/name=cilium", "app=cilium"} {
			list, err := s.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
				LabelSelector: sel,
			})
			if err != nil || len(list.Items) == 0 {
				continue
			}
			var names []string
			for _, p := range list.Items {
				if p.Status.Phase == "Running" {
					names = append(names, p.Name)
				}
			}
			if len(names) > 0 {
				return ns, names, nil
			}
		}
	}
	return "", nil, fmt.Errorf("no running Cilium pods found in %v", ciliumNamespaces())
}

// HubbleStatus reports whether the Hubble agent socket is reachable inside cilium-agent.
type HubbleStatus struct {
	Available bool   `json:"available"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message,omitempty"`
}

// CheckHubbleReady probes one cilium-agent pod to see if hubble observe works.
func (s *Store) CheckHubbleReady(ctx context.Context) HubbleStatus {
	ns, pods, err := s.findAllCiliumPods(ctx)
	if err != nil || len(pods) == 0 {
		return HubbleStatus{Available: false, Message: "Cilium agent pods not found"}
	}
	// Run a one-shot hubble observe --last 1 to test connectivity
	req := s.typed.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pods[0]).
		Namespace(ns).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "cilium-agent",
			Command:   []string{"hubble", "observe", "--last", "1", "-o", "json", "--all-namespaces"},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return HubbleStatus{Available: true, Ready: false, Message: "exec error: " + err.Error()}
	}
	var out, errBuf bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = exec.StreamWithContext(execCtx, remotecommand.StreamOptions{Stdout: &out, Stderr: &errBuf})
	if errBuf.Len() > 0 && out.Len() == 0 {
		return HubbleStatus{Available: true, Ready: false, Message: errBuf.String()}
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
