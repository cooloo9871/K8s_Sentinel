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
	Protocol string `json:"protocol"` // TCP | UDP | ICMP
	// L7 (only when Cilium proxy is active)
	L7Type     string `json:"l7Type,omitempty"` // HTTP | gRPC | DNS | kafka
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPURL    string `json:"httpURL,omitempty"`
	HTTPStatus uint32 `json:"httpStatus,omitempty"`
	DNSQuery   string `json:"dnsQuery,omitempty"`
	DNSRcode   string `json:"dnsRcode,omitempty"`
	// Metadata
	NodeName string `json:"nodeName"`
	IsReply  bool   `json:"isReply"`
}

func ciliumNamespace() string {
	if ns := os.Getenv("CILIUM_NAMESPACE"); ns != "" {
		return ns
	}
	return "kube-system"
}

// DetectCilium returns true when a Cilium DaemonSet is present in the cluster.
func (s *Store) DetectCilium(ctx context.Context) bool {
	if s.typed == nil {
		return false
	}
	for _, ns := range []string{ciliumNamespace(), "cilium", "cilium-system"} {
		if _, err := s.typed.AppsV1().DaemonSets(ns).Get(ctx, "cilium", metav1.GetOptions{}); err == nil {
			return true
		}
	}
	return false
}

// StreamCiliumFlows streams Hubble flows from all Cilium agent pods concurrently.
// It returns when all pod streams exit (error or context done).
func (s *Store) StreamCiliumFlows(ctx context.Context, out chan<- CiliumFlow) error {
	pods, err := s.findAllCiliumPods(ctx)
	if err != nil || len(pods) == 0 {
		return fmt.Errorf("no Cilium agent pods found: %w", err)
	}
	var wg sync.WaitGroup
	for _, pod := range pods {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := s.streamCiliumFromPod(ctx, name, out); err != nil && ctx.Err() == nil {
				log.Printf("cilium-stream: pod %s: %v", name, err)
			}
		}(pod)
	}
	wg.Wait()
	return nil
}

func (s *Store) streamCiliumFromPod(ctx context.Context, podName string, out chan<- CiliumFlow) error {
	req := s.typed.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(ciliumNamespace()).
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
	return <-execDone
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
				Namespace string `json:"namespace"`
				PodName   string `json:"pod_name"`
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
			} `json:"l4"`
			L7 *struct {
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

	// Transport layer
	if f.L4.TCP != nil {
		flow.Protocol = "TCP"
		flow.SrcPort = f.L4.TCP.SrcPort
		flow.DstPort = f.L4.TCP.DstPort
	} else if f.L4.UDP != nil {
		flow.Protocol = "UDP"
		flow.SrcPort = f.L4.UDP.SrcPort
		flow.DstPort = f.L4.UDP.DstPort
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

func (s *Store) findAllCiliumPods(ctx context.Context) ([]string, error) {
	for _, sel := range []string{"k8s-app=cilium", "app.kubernetes.io/name=cilium", "app=cilium"} {
		list, err := s.typed.CoreV1().Pods(ciliumNamespace()).List(ctx, metav1.ListOptions{
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
			return names, nil
		}
	}
	return nil, fmt.Errorf("no running Cilium pods found in namespace %q", ciliumNamespace())
}

// HubbleStatus reports whether the Hubble agent socket is reachable inside cilium-agent.
type HubbleStatus struct {
	Available bool   `json:"available"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message,omitempty"`
}

// CheckHubbleReady probes one cilium-agent pod to see if hubble observe works.
func (s *Store) CheckHubbleReady(ctx context.Context) HubbleStatus {
	pods, err := s.findAllCiliumPods(ctx)
	if err != nil || len(pods) == 0 {
		return HubbleStatus{Available: false, Message: "Cilium agent pods not found"}
	}
	// Run a one-shot hubble observe --last 1 to test connectivity
	req := s.typed.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pods[0]).
		Namespace(ciliumNamespace()).
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
	execCtx, cancel := context.WithTimeout(ctx, 5000000000) // 5s
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
	SrcID, DstID  string
	SrcPod, SrcNs string
	DstPod, DstNs string
	SrcIP, DstIP  string
	Port          string
	Protocol      string
	Verdict       string // "allowed" | "dropped"
	L7Type        string
	HTTPMethod    string
	HTTPURL       string
	HTTPStatus    uint32
	DNSQuery      string
	Count         int
	LastSeen      time.Time
}
