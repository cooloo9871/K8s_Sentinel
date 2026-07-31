package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/sentinel/internal/policy"
)

const annotationCreatedBy = "sentinel.io/created-by"

// PolicyRecord is a policy as returned by the list/get API.
type PolicyRecord struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Scope     string `json:"scope"`     // "cluster" or "namespaced"
	Mode      string `json:"mode"`      // "Monitoring", "Protect", or "Mixed"
	CreatedBy string `json:"createdBy"` // sentinel username or "k8s-apply"
	CreatedAt string `json:"createdAt"`
	RawYAML   string `json:"rawYaml"`
}

// Store manages TracingPolicy and TracingPolicyNamespaced CRDs.
type Store struct {
	client     dynamic.Interface
	typed      *kubernetes.Clientset
	restConfig *rest.Config
	modeMu     sync.RWMutex
	globalMode string // explicitly set by user; never auto-derived from policies
	Discovery  *DiscoveryProfileStore
	Templates  *TemplateStore
	containers *containerResolver

	// Tetragon fan-out broadcast — single stream shared by all consumers
	tetragonMu   sync.RWMutex
	tetragonSubs map[chan TetragonEvent]struct{}

	// Cilium/Hubble fan-out broadcast
	ciliumMu   sync.RWMutex
	ciliumSubs map[chan CiliumFlow]struct{}

	// Cilium topology buffer — unique connections from Hubble flows (TTL 24h)
	ciliumTopoMu      sync.RWMutex
	ciliumTopo        map[string]CiliumTopoEntry // key: "srcID|dstID|port"
	ciliumTopoCleanup uint64                     // triggers lazy eviction every N updates

	// ListClusterIPs cache
	ipCacheMu     sync.RWMutex
	ipCacheData   map[string]IPInfo
	ipCacheExpiry time.Time
	ipCacheTTL    time.Duration
}

// NewStore creates a Store wrapping the given clients. templatesFile is the
// persistence path for custom policy templates (derived from DATA_DIR).
func NewStore(client dynamic.Interface, typed *kubernetes.Clientset, cfg *rest.Config, templatesFile string) *Store {
	return &Store{
		client:       client,
		typed:        typed,
		restConfig:   cfg,
		globalMode:   "Monitoring",
		Discovery:    NewDiscoveryProfileStore(),
		Templates:    NewTemplateStore(templatesFile),
		containers:   newContainerResolver(),
		tetragonSubs: make(map[chan TetragonEvent]struct{}),
		ciliumSubs:   make(map[chan CiliumFlow]struct{}),
		ciliumTopo:   make(map[string]CiliumTopoEntry),
		ipCacheTTL:   30 * time.Second,
	}
}

// ── Tetragon fan-out ────────────────────────────────────────────────────────

// SubscribeTetragon returns a channel that receives Tetragon events and an
// unsubscribe function. All subscribers share a single stream to Tetragon.
func (s *Store) SubscribeTetragon() (<-chan TetragonEvent, func()) {
	ch := make(chan TetragonEvent, 256)
	s.tetragonMu.Lock()
	s.tetragonSubs[ch] = struct{}{}
	s.tetragonMu.Unlock()
	return ch, func() {
		s.tetragonMu.Lock()
		delete(s.tetragonSubs, ch)
		s.tetragonMu.Unlock()
		close(ch)
	}
}

func (s *Store) broadcastTetragon(e TetragonEvent) {
	s.tetragonMu.RLock()
	defer s.tetragonMu.RUnlock()
	for ch := range s.tetragonSubs {
		select {
		case ch <- e:
		default:
		}
	}
}

// StartTetragonBroadcast starts a single Tetragon event stream and fans out
// to all subscribers. Reconnects automatically on error.
func (s *Store) StartTetragonBroadcast(ctx context.Context) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			events := make(chan TetragonEvent, 512)
			go func() {
				defer close(events)
				if err := s.StreamTetragonEvents(ctx, events); err != nil && ctx.Err() == nil {
					log.Printf("tetragon-broadcast: stream error: %v", err)
				}
			}()
			for evt := range events {
				s.broadcastTetragon(evt)
			}
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
}

// ── Cilium fan-out ─────────────────────────────────────────────────────────

func (s *Store) SubscribeCilium() (<-chan CiliumFlow, func()) {
	ch := make(chan CiliumFlow, 256)
	s.ciliumMu.Lock()
	s.ciliumSubs[ch] = struct{}{}
	s.ciliumMu.Unlock()
	return ch, func() {
		s.ciliumMu.Lock()
		delete(s.ciliumSubs, ch)
		s.ciliumMu.Unlock()
		close(ch)
	}
}

func (s *Store) broadcastCilium(f CiliumFlow) {
	s.ciliumMu.RLock()
	defer s.ciliumMu.RUnlock()
	for ch := range s.ciliumSubs {
		select {
		case ch <- f:
		default:
		}
	}
}

// updateCiliumTopo merges a flow into the topology buffer.
func (s *Store) updateCiliumTopo(f CiliumFlow) {
	// Only store flows that are actually forwarded or dropped — skip TRACED,
	// TRANSLATED, ERROR and other intermediate observation-point verdicts.
	if f.Verdict != "allowed" && f.Verdict != "dropped" {
		return
	}
	// Filter reply flows only when the source is a pod (pod→external/pod-to-pod
	// replies). SNAT'd NodePort traffic arrives with is_reply=true but has no
	// source pod (source is a node IP) — keep those so inbound NodePort
	// connections appear in the topology.
	if f.IsReply && f.SrcPod != "" {
		return
	}
	if f.SrcPod == "" && f.SrcIP == "" {
		return
	}
	if f.DstPod == "" && f.DstIP == "" {
		return
	}
	srcID := f.SrcNs + "/" + f.SrcPod
	if f.SrcPod == "" {
		srcID = "ext:" + f.SrcIP
	}
	dstID := f.DstNs + "/" + f.DstPod
	if f.DstPod == "" {
		dstID = "ext:" + f.DstIP
	}
	port := ""
	if f.DstPort > 0 {
		port = fmt.Sprintf("%d", f.DstPort)
	}
	key := srcID + "|" + dstID + "|" + port

	s.ciliumTopoMu.Lock()
	entry := s.ciliumTopo[key]
	entry.SrcID, entry.DstID = srcID, dstID
	entry.SrcPod, entry.SrcNs = f.SrcPod, f.SrcNs
	entry.DstPod, entry.DstNs = f.DstPod, f.DstNs
	entry.SrcIP, entry.DstIP = f.SrcIP, f.DstIP
	entry.Port, entry.Protocol = port, f.Protocol
	entry.Verdict = f.Verdict
	entry.Count++
	entry.LastSeen = time.Now()
	if f.L7Type != "" {
		entry.L7Type = f.L7Type
		if f.HTTPMethod != "" {
			entry.HTTPMethod = f.HTTPMethod
		}
		if f.HTTPURL != "" {
			entry.HTTPURL = f.HTTPURL
		}
		if f.HTTPStatus > 0 {
			entry.HTTPStatus = f.HTTPStatus
		}
		if f.DNSQuery != "" {
			entry.DNSQuery = f.DNSQuery
		}
	}
	s.ciliumTopo[key] = entry

	// Lazy cleanup every 2000 updates — removes entries older than 24h.
	s.ciliumTopoCleanup++
	if s.ciliumTopoCleanup%2000 == 0 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for k, e := range s.ciliumTopo {
			if !e.LastSeen.After(cutoff) {
				delete(s.ciliumTopo, k)
			}
		}
	}
	s.ciliumTopoMu.Unlock()
}

// ListCiliumTopoEntries returns all topology entries seen within the last 24h.
func (s *Store) ListCiliumTopoEntries() []CiliumTopoEntry {
	cutoff := time.Now().Add(-24 * time.Hour)
	s.ciliumTopoMu.RLock()
	defer s.ciliumTopoMu.RUnlock()
	out := make([]CiliumTopoEntry, 0, len(s.ciliumTopo))
	for _, e := range s.ciliumTopo {
		if e.LastSeen.After(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

// HasCiliumTopoData returns true when there is recent Cilium topology data.
func (s *Store) HasCiliumTopoData() bool {
	cutoff := time.Now().Add(-24 * time.Hour)
	s.ciliumTopoMu.RLock()
	defer s.ciliumTopoMu.RUnlock()
	for _, e := range s.ciliumTopo {
		if e.LastSeen.After(cutoff) {
			return true
		}
	}
	return false
}

// StartCiliumBroadcast streams Hubble flows from all cilium-agent pods and
// fans out to all subscribers. No-op when Cilium is not detected.
func (s *Store) StartCiliumBroadcast(ctx context.Context) {
	go func() {
		if !s.DetectCilium(ctx) {
			log.Printf("cilium-broadcast: Cilium not detected, skipping")
			return
		}
		log.Printf("cilium-broadcast: Cilium detected, starting flow stream")
		for {
			if ctx.Err() != nil {
				return
			}
			flows := make(chan CiliumFlow, 512)
			go func() {
				defer close(flows)
				if err := s.StreamCiliumFlows(ctx, flows); err != nil && ctx.Err() == nil {
					log.Printf("cilium-broadcast: stream error: %v", err)
				}
			}()
			for f := range flows {
				s.updateCiliumTopo(f)
				// Only broadcast flows that pass the topology filter so SSE
				// subscribers don't receive TRACED/TRANSLATED noise.
				if f.Verdict == "allowed" || f.Verdict == "dropped" {
					s.broadcastCilium(f)
				}
			}
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}()
}

// ── ListClusterIPs with TTL cache ──────────────────────────────────────────

// CachedClusterIPs returns IP→IPInfo, refreshing at most every ipCacheTTL.
func (s *Store) CachedClusterIPs(ctx context.Context) (map[string]IPInfo, error) {
	s.ipCacheMu.RLock()
	if s.ipCacheData != nil && time.Now().Before(s.ipCacheExpiry) {
		data := s.ipCacheData
		s.ipCacheMu.RUnlock()
		return data, nil
	}
	s.ipCacheMu.RUnlock()

	// Cache miss — refresh
	fresh, err := s.ListClusterIPs(ctx)
	if err != nil {
		// Return stale data if available
		s.ipCacheMu.RLock()
		stale := s.ipCacheData
		s.ipCacheMu.RUnlock()
		if stale != nil {
			return stale, nil
		}
		return nil, err
	}

	s.ipCacheMu.Lock()
	s.ipCacheData = fresh
	s.ipCacheExpiry = time.Now().Add(s.ipCacheTTL)
	s.ipCacheMu.Unlock()
	return fresh, nil
}

// List returns all cluster-wide and namespaced policies.
func (s *Store) List(ctx context.Context) ([]PolicyRecord, error) {
	var records []PolicyRecord

	clusterList, err := s.client.Resource(tracingPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list TracingPolicy: %w", err)
	}
	for _, item := range clusterList.Items {
		r, err := toRecord(item, "cluster")
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	nsList, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list TracingPolicyNamespaced: %w", err)
	}
	for _, item := range nsList.Items {
		r, err := toRecord(item, "namespaced")
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, nil
}

// Get returns a single policy by name and optional namespace.
func (s *Store) Get(ctx context.Context, name, namespace string) (PolicyRecord, error) {
	var item *unstructured.Unstructured
	var err error
	scope := "cluster"

	if namespace != "" {
		scope = "namespaced"
		item, err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		item, err = s.client.Resource(tracingPolicyGVR).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("get policy %q: %w", name, err)
	}
	return toRecord(*item, scope)
}

// Apply creates or updates a policy from a TracingPolicy struct.
func (s *Store) Apply(ctx context.Context, tp policy.TracingPolicy, createdBy string) error {
	data, err := json.Marshal(tp)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal to unstructured: %w", err)
	}

	name := tp.Metadata.Name
	ns := tp.Metadata.Namespace

	if ns != "" {
		return s.applyNamespaced(ctx, ns, name, obj, createdBy)
	}
	return s.applyCluster(ctx, name, obj, createdBy)
}

// ApplyRaw applies a raw YAML string to the cluster, detecting scope from the namespace field.
func (s *Store) ApplyRaw(ctx context.Context, rawYAML string, createdBy string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal YAML: %w", err)
	}

	name := obj.GetName()
	ns := obj.GetNamespace()

	if ns != "" {
		return s.applyNamespaced(ctx, ns, name, obj, createdBy)
	}
	return s.applyCluster(ctx, name, obj, createdBy)
}

// Delete removes a policy by name and optional namespace.
func (s *Store) Delete(ctx context.Context, name, namespace string) error {
	var err error
	if namespace != "" {
		err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	} else {
		err = s.client.Resource(tracingPolicyGVR).Delete(ctx, name, metav1.DeleteOptions{})
	}
	if err != nil {
		return fmt.Errorf("delete policy %q: %w", name, err)
	}
	return nil
}

// SecurityEvent is a security-relevant Kubernetes event returned by the API.
type SecurityEvent struct {
	Namespace         string `json:"namespace"`
	InvolvedKind      string `json:"involvedKind"`
	InvolvedName      string `json:"involvedName"`
	InvolvedNamespace string `json:"involvedNamespace"`
	Reason            string `json:"reason"`
	Message           string `json:"message"`
	Type              string `json:"type"`
	Count             int64  `json:"count"`
	FirstTime         string `json:"firstTime"`
	LastTime          string `json:"lastTime"`
	Source            string `json:"source"`
}

// ListSecurityEvents returns Warning-type events and Tetragon events across all namespaces.
func (s *Store) ListSecurityEvents(ctx context.Context) ([]SecurityEvent, error) {
	list, err := s.client.Resource(eventsGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	var events []SecurityEvent
	for _, item := range list.Items {
		evType, _, _ := unstructured.NestedString(item.Object, "type")
		source, _, _ := unstructured.NestedString(item.Object, "source", "component")

		isTetragon := strings.Contains(strings.ToLower(source), "tetragon")
		if evType != "Warning" && !isTetragon {
			continue
		}

		reason, _, _ := unstructured.NestedString(item.Object, "reason")
		message, _, _ := unstructured.NestedString(item.Object, "message")
		involvedKind, _, _ := unstructured.NestedString(item.Object, "involvedObject", "kind")
		involvedName, _, _ := unstructured.NestedString(item.Object, "involvedObject", "name")
		involvedNS, _, _ := unstructured.NestedString(item.Object, "involvedObject", "namespace")
		firstTime, _, _ := unstructured.NestedString(item.Object, "firstTimestamp")
		lastTime, _, _ := unstructured.NestedString(item.Object, "lastTimestamp")

		var count int64
		if v, ok, _ := unstructured.NestedFieldNoCopy(item.Object, "count"); ok {
			if n, ok := v.(int64); ok {
				count = n
			}
		}

		events = append(events, SecurityEvent{
			Namespace:         item.GetNamespace(),
			InvolvedKind:      involvedKind,
			InvolvedName:      involvedName,
			InvolvedNamespace: involvedNS,
			Reason:            reason,
			Message:           message,
			Type:              evType,
			Count:             count,
			FirstTime:         firstTime,
			LastTime:          lastTime,
			Source:            source,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].LastTime > events[j].LastTime
	})

	return events, nil
}

// noisyLabelPrefixes are auto-generated labels that are not useful as pod selectors.
var noisyLabelPrefixes = []string{
	"pod-template-hash",
	"controller-revision-hash",
	"statefulset.kubernetes.io/pod-name",
}

// GetPodLabels returns the meaningful labels of a pod, filtering auto-generated noise.
func (s *Store) GetPodLabels(ctx context.Context, namespace, name string) (map[string]string, error) {
	pod, err := s.typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}
	labels := make(map[string]string)
outer:
	for k, v := range pod.Labels {
		for _, noisy := range noisyLabelPrefixes {
			if strings.HasPrefix(k, noisy) {
				continue outer
			}
		}
		labels[k] = v
	}
	return labels, nil
}

// ListNamespaces returns all namespace names in the cluster.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	list, err := s.client.Resource(namespaceGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.GetName())
	}
	return names, nil
}

// IPInfo holds the resolved identity for a cluster IP.
type IPInfo struct {
	IP        string
	Name      string
	Namespace string
	Kind      string // "pod" | "service"
}

// ListClusterIPs returns a map of IP → IPInfo for all pods and services in the cluster.
// Used by the network topology handler to resolve destination IPs to workload names.
func (s *Store) ListClusterIPs(ctx context.Context) (map[string]IPInfo, error) {
	result := make(map[string]IPInfo)

	pods, podErr := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if podErr == nil {
		for _, p := range pods.Items {
			// Skip hostNetwork pods — they share the node IP, which causes
			// connections to other processes on the same node (e.g. kube-apiserver)
			// to be misattributed to this pod.
			if p.Spec.HostNetwork {
				continue
			}
			if p.Status.PodIP != "" {
				result[p.Status.PodIP] = IPInfo{
					IP:        p.Status.PodIP,
					Name:      p.Name,
					Namespace: p.Namespace,
					Kind:      "pod",
				}
			}
		}
	}

	svcs, svcErr := s.typed.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if svcErr == nil {
		for _, svc := range svcs.Items {
			if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
				result[svc.Spec.ClusterIP] = IPInfo{
					IP:        svc.Spec.ClusterIP,
					Name:      svc.Name,
					Namespace: svc.Namespace,
					Kind:      "service",
				}
			}
		}
	}

	if podErr != nil && svcErr != nil {
		return nil, fmt.Errorf("list cluster IPs: pods: %v; services: %v", podErr, svcErr)
	}

	return result, nil
}

// NodeIPMap holds per-node information for topology IP classification.
type NodeIPMap struct {
	IPToName map[string]string // primary node IP → nodeName (shown as "node")
	SkipIPs  map[string]bool   // cilium_host / internal interface IPs (hidden)
	PodCIDRs []string          // all pod CIDRs across all nodes
}

// ListNodeIPMap returns node physical IPs, cilium internal IPs, and pod CIDRs
// used to distinguish node IPs from external IPs and to hide per-node internal
// interface addresses (e.g. cilium_host) in the topology graph.
func (s *Store) ListNodeIPMap(ctx context.Context) NodeIPMap {
	result := NodeIPMap{
		IPToName: make(map[string]string),
		SkipIPs:  make(map[string]bool),
	}
	if s.typed == nil {
		return result
	}
	nodes, err := s.typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, node := range nodes.Items {
			for _, addr := range node.Status.Addresses {
				if addr.Type == corev1.NodeInternalIP || addr.Type == corev1.NodeExternalIP {
					result.IPToName[addr.Address] = node.Name
				}
			}
			if node.Spec.PodCIDR != "" {
				result.PodCIDRs = append(result.PodCIDRs, node.Spec.PodCIDR)
			}
			result.PodCIDRs = append(result.PodCIDRs, node.Spec.PodCIDRs...)
		}
	}

	// Cilium uses cluster-pool IPAM by default and does NOT populate
	// node.Spec.PodCIDR. The authoritative per-node pod CIDRs and the
	// cilium_host (CiliumInternalIP) addresses live in the CiliumNode CR.
	if s.client != nil {
		cnList, cnErr := s.client.Resource(ciliumNodeGVR).List(ctx, metav1.ListOptions{})
		if cnErr == nil {
			for _, cn := range cnList.Items {
				spec, _, _ := unstructured.NestedMap(cn.Object, "spec")
				if spec == nil {
					continue
				}
				// spec.addresses[] — collect CiliumInternalIP as skip targets
				if addrs, ok := spec["addresses"].([]interface{}); ok {
					for _, a := range addrs {
						addr, ok := a.(map[string]interface{})
						if !ok {
							continue
						}
						ipType, _ := addr["type"].(string)
						ip, _ := addr["ip"].(string)
						if ip == "" {
							continue
						}
						if ipType == "CiliumInternalIP" {
							result.SkipIPs[ip] = true
						}
					}
				}
				// spec.ipam.podCIDRs[] — authoritative pod CIDRs
				if podCIDRs, _, _ := unstructured.NestedStringSlice(cn.Object, "spec", "ipam", "podCIDRs"); len(podCIDRs) > 0 {
					result.PodCIDRs = append(result.PodCIDRs, podCIDRs...)
				}
			}
		}
	}
	return result
}

// IPInCIDRs returns true when ip falls within any of the given CIDR ranges.
func IPInCIDRs(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// GetMode returns the explicitly set global enforcement mode.
// It never auto-derives the mode from policy actions.
func (s *Store) GetMode(ctx context.Context) (string, error) {
	s.modeMu.RLock()
	defer s.modeMu.RUnlock()
	return s.globalMode, nil
}

// SetMode applies the enforcement mode to all policies first, then updates the
// cached globalMode. If any policy apply fails the cache is not updated, so
// the displayed mode stays consistent with what was actually applied.
func (s *Store) SetMode(ctx context.Context, mode string) error {
	action := policy.ActionPost
	if mode == "Protect" {
		action = policy.ActionSigkill
	}

	records, err := s.List(ctx)
	if err != nil {
		return err
	}

	for _, r := range records {
		var tp policy.TracingPolicy
		if err := yaml.Unmarshal([]byte(r.RawYAML), &tp); err != nil {
			return fmt.Errorf("parse policy %q: %w", r.Name, err)
		}
		for i := range tp.Spec.KProbes {
			for j := range tp.Spec.KProbes[i].Selectors {
				for k := range tp.Spec.KProbes[i].Selectors[j].MatchActions {
					tp.Spec.KProbes[i].Selectors[j].MatchActions[k].Action = action
				}
			}
		}
		if err := s.Apply(ctx, tp, ""); err != nil {
			return fmt.Errorf("apply policy %q: %w", r.Name, err)
		}
	}

	// Only update cached mode after all policies are successfully applied.
	s.modeMu.Lock()
	s.globalMode = mode
	s.modeMu.Unlock()
	return nil
}

func setCreatedByAnnotation(obj *unstructured.Unstructured, createdBy string) {
	if createdBy == "" {
		return
	}
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[annotationCreatedBy] = createdBy
	obj.SetAnnotations(ann)
}

func preserveCreatedBy(obj, existing *unstructured.Unstructured) {
	if v := existing.GetAnnotations()[annotationCreatedBy]; v != "" {
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann[annotationCreatedBy] = v
		obj.SetAnnotations(ann)
	}
}

func (s *Store) applyCluster(ctx context.Context, name string, obj *unstructured.Unstructured, createdBy string) error {
	setCreatedByAnnotation(obj, createdBy)
	_, err := s.client.Resource(tracingPolicyGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(tracingPolicyGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	preserveCreatedBy(obj, existing)
	_, err = s.client.Resource(tracingPolicyGVR).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *Store) applyNamespaced(ctx context.Context, ns, name string, obj *unstructured.Unstructured, createdBy string) error {
	setCreatedByAnnotation(obj, createdBy)
	_, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	preserveCreatedBy(obj, existing)
	_, err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func toRecord(item unstructured.Unstructured, scope string) (PolicyRecord, error) {
	rawJSON, err := json.Marshal(item.Object)
	if err != nil {
		return PolicyRecord{}, err
	}
	rawYAML, err := yaml.JSONToYAML(rawJSON)
	if err != nil {
		return PolicyRecord{}, err
	}
	createdAt := ""
	if ts := item.GetCreationTimestamp(); !ts.IsZero() {
		createdAt = ts.UTC().Format("2006-01-02T15:04:05Z")
	}
	createdBy := "k8s-apply"
	if v := item.GetAnnotations()[annotationCreatedBy]; v != "" {
		createdBy = v
	}
	return PolicyRecord{
		Name:      item.GetName(),
		Namespace: item.GetNamespace(),
		Scope:     scope,
		Mode:      detectMode(string(rawYAML)),
		CreatedBy: createdBy,
		CreatedAt: createdAt,
		RawYAML:   string(rawYAML),
	}, nil
}

// detectMode returns "Monitoring", "Protect", or "Mixed" based on kprobe actions.
func detectMode(rawYAML string) string {
	var tp policy.TracingPolicy
	if err := yaml.Unmarshal([]byte(rawYAML), &tp); err != nil {
		return "Monitoring"
	}
	post, kill := 0, 0
	for _, kp := range tp.Spec.KProbes {
		for _, sel := range kp.Selectors {
			for _, act := range sel.MatchActions {
				switch act.Action {
				case policy.ActionSigkill:
					kill++
				case policy.ActionPost:
					post++
					// Unknown actions are intentionally ignored — they don't
					// contribute to either counter, matching GetMode's behaviour.
				}
			}
		}
	}
	if kill == 0 {
		return "Monitoring"
	}
	if post == 0 {
		return "Protect"
	}
	return "Mixed"
}

// SetPolicyMode updates all kprobe actions in a single policy.
func (s *Store) SetPolicyMode(ctx context.Context, name, namespace, mode string) error {
	action := policy.ActionPost
	if mode == "Protect" {
		action = policy.ActionSigkill
	}

	record, err := s.Get(ctx, name, namespace)
	if err != nil {
		return err
	}

	var tp policy.TracingPolicy
	if err := yaml.Unmarshal([]byte(record.RawYAML), &tp); err != nil {
		return fmt.Errorf("parse policy %q: %w", name, err)
	}
	for i := range tp.Spec.KProbes {
		for j := range tp.Spec.KProbes[i].Selectors {
			for k := range tp.Spec.KProbes[i].Selectors[j].MatchActions {
				tp.Spec.KProbes[i].Selectors[j].MatchActions[k].Action = action
			}
		}
	}
	return s.Apply(ctx, tp, "")
}

// ListServicePodNames returns a map of "namespace/serviceName" → pod names
// for all services in the cluster, using the Endpoints API.
func (s *Store) ListServicePodNames(ctx context.Context) (map[string][]string, error) {
	if s.typed == nil {
		return nil, nil
	}
	list, err := s.typed.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string, len(list.Items))
	for _, ep := range list.Items {
		key := ep.Namespace + "/" + ep.Name
		var pods []string
		for _, sub := range ep.Subsets {
			for _, addr := range sub.Addresses {
				if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
					pods = append(pods, addr.TargetRef.Name)
				}
			}
		}
		if len(pods) > 0 {
			result[key] = pods
		}
	}
	return result, nil
}
