package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/K8s_Sentinel/internal/policy"
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
	client dynamic.Interface
	// An interface, not *kubernetes.Clientset, so tests can inject a fake. Only
	// CoreV1/AppsV1/NetworkingV1 are used, all of which it covers.
	typed      kubernetes.Interface
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

	// Cilium topology buffer — unique connections from Hubble flows, kept for
	// ciliumTopoWindow
	ciliumTopoMu      sync.RWMutex
	ciliumTopo        map[string]CiliumTopoEntry // key: "srcID|dstID|port"
	ciliumTopoCleanup uint64                     // triggers lazy eviction every N updates
	// Whether any flow has ever arrived, which the window cannot answer. A
	// cluster that has been quiet for 15 minutes looks identical to one where
	// Hubble delivers nothing, and only one of those is a problem.
	ciliumFlowSeen bool

	// ListClusterIPs cache
	ipCacheMu     sync.RWMutex
	ipCacheData   map[string]IPInfo
	ipCacheExpiry time.Time
	ipCacheTTL    time.Duration

	// Pod exposure cache (NodePort/LB/Ingress/hostNetwork paths)
	exposureMu     sync.RWMutex
	exposureData   map[string][]Exposure
	exposureExpiry time.Time

	// Policy attribution cache (CNP selectors + pod labels), used to name the
	// policy behind a denial Hubble could not correlate
	attrMu     sync.RWMutex
	attrData   *attributionData
	attrExpiry time.Time
	// Pods already reported as missing from the attribution cache, so the warning
	// is logged once each rather than once per flow.
	warnedPods sync.Map

	// Node address map cache — see CachedNodeIPMap.
	nodeIPMu     sync.RWMutex
	nodeIPData   *NodeIPMap
	nodeIPExpiry time.Time
}

// NewStore creates a Store wrapping the given clients. templatesFile is the
// persistence path for custom policy templates (derived from DATA_DIR).
// The rest.Config parameter is retained for signature stability but no longer
// used: event collection moved from kubectl exec to the Tetragon and Hubble
// gRPC APIs, so the Store dials pod IPs directly rather than opening exec
// streams.
func NewStore(client dynamic.Interface, typed kubernetes.Interface, _ *rest.Config, templatesFile string) *Store {
	return &Store{
		client:       client,
		typed:        typed,
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

// ciliumTopoWindow is how far back the topology looks. The graph shows what is
// happening now, so a connection that has stopped drops off rather than being
// drawn as though it were live. Long enough that periodic traffic — a workload
// that polls every few minutes — does not make its edge flicker in and out.
const ciliumTopoWindow = 15 * time.Minute

// updateCiliumTopo merges a flow into the topology buffer.
func (s *Store) updateCiliumTopo(f CiliumFlow) {
	// Only store flows that are actually forwarded or dropped — skip TRACED,
	// TRANSLATED, ERROR and other intermediate observation-point verdicts.
	if f.Verdict != "allowed" && f.Verdict != "dropped" {
		return
	}
	// Reply-direction flows never define an edge — an edge's direction is the
	// connection-initiation direction (conntrack request side). Replies of
	// pod-initiated egress arrive as ext→pod with no source pod and would
	// invert the topology: a pod curling an external site appeared to RECEIVE
	// external traffic, falsely triggering the undeclared-exposure warning.
	// Genuine inbound requests (world→pod) carry is_reply=false and are kept.
	if f.IsReply {
		return
	}
	// An ICMP error names the reporter as the source, so an edge built from one
	// says something reached the pod when in fact the pod's own packet failed to
	// reach somewhere else. Same reasoning as replies: only the request side
	// defines a connection.
	if f.IsICMPError() {
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
		// Collapse ephemeral client-side ports (Linux default range starts at
		// 32768) into one bucket so the buffer doesn't grow per connection.
		if f.DstPort >= 32768 {
			port = "dynamic"
		} else {
			port = fmt.Sprintf("%d", f.DstPort)
		}
	}
	// The verdict is part of the identity. Leaving it out let a later allowed
	// flow overwrite a denial in place, turning a blocked edge green on the
	// graph while the policy was still denying — and it made the handler's
	// "blocked wins over allowed" rule unreachable, since only one of the two
	// could ever be in the buffer.
	key := srcID + "|" + dstID + "|" + port + "|" + f.Verdict

	s.ciliumTopoMu.Lock()
	entry := s.ciliumTopo[key]
	entry.Key = key
	entry.SrcID, entry.DstID = srcID, dstID
	entry.SrcPod, entry.SrcNs = f.SrcPod, f.SrcNs
	entry.DstPod, entry.DstNs = f.DstPod, f.DstNs
	entry.SrcIP, entry.DstIP = f.SrcIP, f.DstIP
	entry.SrcIsWorld = f.SrcIsWorld
	entry.Port, entry.Protocol = port, f.Protocol
	entry.Verdict = f.Verdict
	if f.Verdict == "dropped" {
		// Not every drop for the same pair carries correlation data, so only
		// overwrite when this flow actually names something. Assigning
		// unconditionally let a later uncorrelated drop blank out a name already
		// resolved, and the graph's "Blocked by policy" lost its policy.
		if f.PolicyName != "" {
			entry.PolicyName = f.PolicyName
		}
		if f.Direction != "" {
			entry.Direction = f.Direction
		}
	}
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
	s.ciliumFlowSeen = true

	// Lazy cleanup every 2000 updates — removes entries past the window.
	s.ciliumTopoCleanup++
	if s.ciliumTopoCleanup%2000 == 0 {
		cutoff := time.Now().Add(-ciliumTopoWindow)
		for k, e := range s.ciliumTopo {
			if !e.LastSeen.After(cutoff) {
				delete(s.ciliumTopo, k)
			}
		}
	}
	s.ciliumTopoMu.Unlock()
}

// PruneCiliumTopo removes the given entries from the buffer. Used to evict
// connections whose pod endpoints no longer exist, rather than holding them
// until they fall out of the window.
func (s *Store) PruneCiliumTopo(keys []string) {
	if len(keys) == 0 {
		return
	}
	s.ciliumTopoMu.Lock()
	for _, k := range keys {
		delete(s.ciliumTopo, k)
	}
	s.ciliumTopoMu.Unlock()
}

// PruneBlockedFor drops the recorded denials involving a pod.
//
// Used when quarantine is lifted. Those drops are the ones Sentinel itself
// caused, and releasing the pod is the moment it knows they have stopped —
// there is no reason to wait for evidence. Left to age out instead, the graph
// went on reporting "Blocked by policy" for up to the whole fifteen-minute
// window after the pod was already reachable, and could name no policy for it
// either: the one that dropped the traffic no longer selects the pod.
func (s *Store) PruneBlockedFor(namespace, pod string) {
	if pod == "" {
		return
	}
	s.ciliumTopoMu.Lock()
	defer s.ciliumTopoMu.Unlock()
	for k, e := range s.ciliumTopo {
		if e.Verdict != "dropped" {
			continue
		}
		if (e.SrcNs == namespace && e.SrcPod == pod) || (e.DstNs == namespace && e.DstPod == pod) {
			delete(s.ciliumTopo, k)
		}
	}
}

// ListCiliumTopoEntries returns the topology entries seen within the window.
func (s *Store) ListCiliumTopoEntries() []CiliumTopoEntry {
	cutoff := time.Now().Add(-ciliumTopoWindow)
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
	cutoff := time.Now().Add(-ciliumTopoWindow)
	s.ciliumTopoMu.RLock()
	defer s.ciliumTopoMu.RUnlock()
	for _, e := range s.ciliumTopo {
		if e.LastSeen.After(cutoff) {
			return true
		}
	}
	return false
}

// EverSawCiliumFlow reports whether any flow has been recorded since startup,
// regardless of the window. Tells a quiet cluster apart from one where Hubble is
// not delivering.
func (s *Store) EverSawCiliumFlow() bool {
	s.ciliumTopoMu.RLock()
	defer s.ciliumTopoMu.RUnlock()
	return s.ciliumFlowSeen
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
				// Network policy denials are security events: publish them on the
				// shared bus so the security store, webhook alerts and syslog
				// forwarding all pick them up without each subscribing to Cilium.
				if evt, ok := s.SynthesizePolicyDenyEvent(ctx, f); ok {
					s.broadcastTetragon(evt)
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

	// Not fromCache: the editor navigates straight back to this list after
	// applying, and a watch cache lagging by a moment reads as the save failing.
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

	// The YAML editor shows the object as the cluster returned it, so an edited
	// manifest carries server-owned metadata. Create refuses a resourceVersion
	// outright — before the AlreadyExists that routes to Update — so without
	// this an edit could never save, while the same YAML passed kubectl edit.
	// The update paths below re-read the current resourceVersion themselves.
	obj.SetResourceVersion("")
	obj.SetUID("")
	obj.SetManagedFields(nil)

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
	list, err := s.client.Resource(namespaceGVR).List(ctx, fromCache)
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

	pods, podErr := s.typed.CoreV1().Pods("").List(ctx, fromCache)
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

	svcs, svcErr := s.typed.CoreV1().Services("").List(ctx, fromCache)
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
	// Node IP → nodeName, covering both the physical addresses and cilium_host.
	// cilium_host used to be hidden instead, which silently dropped any edge it
	// appeared on — including inbound NodePort traffic, which Cilium SNATs to the
	// ingress node's cilium_host when the backend pod is on another node. Naming
	// the node is truthful: the traffic did arrive through it.
	IPToName map[string]string
	PodCIDRs []string // all pod CIDRs across all nodes
}

// CachedNodeIPMap returns the node address map, refreshed at most every 30
// seconds like the other lookups.
//
// It was the one uncached list on the topology path, so it ran twice — nodes and
// CiliumNodes — on every poll of every open tab, while everything else beside it
// was served from a cache. Node addresses change when a node joins or leaves,
// which is not something worth two API calls a minute per viewer.
func (s *Store) CachedNodeIPMap(ctx context.Context) NodeIPMap {
	s.nodeIPMu.RLock()
	if s.nodeIPData != nil && time.Now().Before(s.nodeIPExpiry) {
		d := *s.nodeIPData
		s.nodeIPMu.RUnlock()
		return d
	}
	s.nodeIPMu.RUnlock()

	fresh := s.ListNodeIPMap(ctx)
	// An empty map means the lookup failed. Caching that would classify every
	// node address as external for the next 30 seconds.
	if len(fresh.IPToName) == 0 {
		return fresh
	}
	s.nodeIPMu.Lock()
	s.nodeIPData = &fresh
	s.nodeIPExpiry = time.Now().Add(30 * time.Second)
	s.nodeIPMu.Unlock()
	return fresh
}

// ListNodeIPMap returns node IPs — physical and cilium_host — and pod CIDRs,
// used to tell node addresses from external ones in the topology graph.
func (s *Store) ListNodeIPMap(ctx context.Context) NodeIPMap {
	result := NodeIPMap{IPToName: make(map[string]string)}
	if s.typed == nil {
		return result
	}
	nodes, err := s.typed.CoreV1().Nodes().List(ctx, fromCache)
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
		cnList, cnErr := s.client.Resource(ciliumNodeGVR).List(ctx, fromCache)
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
							result.IPToName[ip] = cn.GetName()
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

// IsLinkLocal reports whether the address is link-local — 169.254.0.0/16 or
// fe80::/10. RFC 3927 addresses are not routable beyond the local link, so one
// can never be a client from outside the cluster, whatever else is unknown
// about it.
func IsLinkLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLinkLocalUnicast()
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
	records, err := s.List(ctx)
	if err != nil {
		return err
	}
	action := modeAction(mode)
	for _, r := range records {
		if err := s.setPolicyAction(ctx, r.Name, r.Namespace, action); err != nil {
			return fmt.Errorf("apply policy %q: %w", r.Name, err)
		}
	}

	// Only update cached mode after all policies are successfully applied.
	s.modeMu.Lock()
	s.globalMode = mode
	s.modeMu.Unlock()
	return nil
}

// modeAction is the Tetragon action a mode applies.
func modeAction(mode string) string {
	if mode == "Protect" {
		return policy.ActionSigkill
	}
	return policy.ActionPost
}

// probeFields are the spec sections that can carry selectors with actions.
// kprobes is the only one Sentinel's own builder produces, but a policy written
// by hand can use any of them and a mode switch has to reach all of it.
var probeFields = []string{"kprobes", "tracepoints", "uprobes", "lsmhooks"}

// setPolicyAction rewrites one policy's enforcement actions in the cluster.
//
// The object is fetched and edited in place. Going through policy.TracingPolicy
// instead — marshal the struct, apply it back — was silently destructive: that
// struct models only podSelector and kprobes, so switching the mode deleted
// every field it does not know about. A policy applied with kubectl carrying
// tracepoints, enforcers, matchNamespaces, tags or message lost them, and
// nothing said so until the policy stopped doing what it was written to do.
func (s *Store) setPolicyAction(ctx context.Context, name, namespace, action string) error {
	var ri dynamic.ResourceInterface = s.client.Resource(tracingPolicyGVR)
	if namespace != "" {
		ri = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace)
	}
	obj, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if rewriteActions(obj.Object, action) == 0 {
		return nil // nothing to switch — leave the object untouched
	}
	_, err = ri.Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

// rewriteActions sets every enforcement action in the object to action, in place,
// and reports how many it changed.
//
// Only actions that are already Post or Sigkill are touched. The others —
// Override, Signal, FollowFD, NoPost — say something a mode switch has no
// business rewriting, and the previous code overwrote them all indiscriminately.
func rewriteActions(obj map[string]any, action string) int {
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return 0
	}
	changed := 0
	for _, field := range probeFields {
		probes, _ := spec[field].([]any)
		for _, p := range probes {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			sels, _ := pm["selectors"].([]any)
			for _, sel := range sels {
				sm, ok := sel.(map[string]any)
				if !ok {
					continue
				}
				acts, _ := sm["matchActions"].([]any)
				for _, a := range acts {
					am, ok := a.(map[string]any)
					if !ok {
						continue
					}
					if cur, _ := am["action"].(string); cur == policy.ActionPost || cur == policy.ActionSigkill {
						am["action"] = action
						changed++
					}
				}
			}
		}
	}
	return changed
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
		Mode:      detectMode(item.Object),
		CreatedBy: createdBy,
		CreatedAt: createdAt,
		RawYAML:   string(rawYAML),
	}, nil
}

// detectMode returns "Monitoring", "Protect", or "Mixed" from the policy's
// actions. It walks the same spec sections the mode switch writes, so what the
// list column reports and what flipping the mode changes cannot disagree —
// reading kprobes alone made a hand-written tracepoint policy that kills report
// itself as Monitoring.
//
// Actions other than Post and Sigkill are deliberately not counted: they say
// nothing about enforcement mode.
func detectMode(obj map[string]any) string {
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return "Monitoring"
	}
	post, kill := 0, 0
	for _, field := range probeFields {
		probes, _ := spec[field].([]any)
		for _, p := range probes {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			sels, _ := pm["selectors"].([]any)
			for _, sel := range sels {
				sm, ok := sel.(map[string]any)
				if !ok {
					continue
				}
				acts, _ := sm["matchActions"].([]any)
				for _, a := range acts {
					am, ok := a.(map[string]any)
					if !ok {
						continue
					}
					switch act, _ := am["action"].(string); act {
					case policy.ActionSigkill:
						kill++
					case policy.ActionPost:
						post++
					}
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

// SetPolicyMode updates the enforcement actions in a single policy.
func (s *Store) SetPolicyMode(ctx context.Context, name, namespace, mode string) error {
	return s.setPolicyAction(ctx, name, namespace, modeAction(mode))
}

// ListServicePodNames returns a map of "namespace/serviceName" → pod names
// for all services in the cluster, using the Endpoints API.
func (s *Store) ListServicePodNames(ctx context.Context) (map[string][]string, error) {
	if s.typed == nil {
		return nil, nil
	}
	// EndpointSlice, not Endpoints. The older API is deprecated as of Kubernetes
	// 1.33, and a single Endpoints object truncates at 1000 addresses — which
	// would silently drop the rest of a large Service's pods out of exposure
	// detection, the one place a missing pod reads as "not reachable".
	list, err := s.typed.DiscoveryV1().EndpointSlices("").List(ctx, fromCache)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string, len(list.Items))
	seen := make(map[string]bool)
	for _, slice := range list.Items {
		svc := slice.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue // not backing a Service
		}
		key := slice.Namespace + "/" + svc
		for _, ep := range slice.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			// Readiness is deliberately not consulted: a pod that is momentarily
			// unready is still configured to be reached this way, and exposure is
			// a question about configuration.
			//
			// A Service spans several slices, so the same pod can be listed twice
			// and would otherwise produce the exposure twice.
			if id := key + "/" + ep.TargetRef.Name; !seen[id] {
				seen[id] = true
				result[key] = append(result[key], ep.TargetRef.Name)
			}
		}
	}
	return result, nil
}

// SeedCiliumTopoForTest replaces the topology buffer. Test-only: the buffer is
// otherwise filled by the Hubble stream, which a unit test has no way to drive.
func (s *Store) SeedCiliumTopoForTest(entries []CiliumTopoEntry) {
	s.ciliumTopoMu.Lock()
	s.ciliumTopo = make(map[string]CiliumTopoEntry, len(entries))
	for _, e := range entries {
		s.ciliumTopo[e.Key] = e
	}
	s.ciliumFlowSeen = len(entries) > 0
	s.ciliumTopoMu.Unlock()
}
