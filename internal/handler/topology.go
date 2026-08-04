package handler

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

type TopologyNode struct {
	ID        string         `json:"id"`
	Label     string         `json:"label"`
	Pod       string         `json:"pod"`
	Namespace string         `json:"namespace"`
	Kind      string         `json:"kind"` // "pod" | "external" | "node"
	IP        string         `json:"ip,omitempty"`
	Exposures []k8s.Exposure `json:"exposures,omitempty"` // static attack-surface paths (pod nodes only)
}

// PortStat is one destination port's share of an aggregated edge.
type PortStat struct {
	Port  string `json:"port"`
	Count int    `json:"count"`
}

type TopologyEdge struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	DestIP  string `json:"destIp,omitempty"`
	Count   int    `json:"count"`
	Blocked bool   `json:"blocked"`
	// Which policy denied the traffic. Named by Hubble correlation when an
	// explicit deny rule fired, otherwise resolved from the policies that
	// govern the pod. Empty when neither can identify one.
	DeniedBy string `json:"deniedBy,omitempty"`
	// When this connection was last observed. Flows are buffered for 24h, so an
	// edge can describe something that stopped happening hours ago — the UI needs
	// this to say so rather than presenting it as current.
	LastSeen string     `json:"lastSeen,omitempty"`
	Ports    []PortStat `json:"ports,omitempty"` // per-port breakdown, count-desc
	// L7 fields (populated from Cilium/Hubble data)
	L7Type     string `json:"l7Type,omitempty"`
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPURL    string `json:"httpURL,omitempty"`
	HTTPStatus uint32 `json:"httpStatus,omitempty"`
	DNSQuery   string `json:"dnsQuery,omitempty"`
}

// normalizePort collapses ephemeral ports (Linux default range starts at
// 32768) into one "dynamic" bucket so a single logical connection pair does
// not explode into N parallel edges keyed by client-side ports.
func normalizePort(port string) string {
	if p, err := strconv.Atoi(port); err == nil && p >= 32768 {
		return "dynamic"
	}
	return port
}

// portStats flattens a port→count map into a count-descending slice.
func portStats(ports map[string]int) []PortStat {
	out := make([]PortStat, 0, len(ports))
	for p, c := range ports {
		out = append(out, PortStat{Port: p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

type TopologyResponse struct {
	Nodes             []TopologyNode `json:"nodes"`
	Edges             []TopologyEdge `json:"edges"`
	HasNetworkEvents  bool           `json:"hasNetworkEvents"`
	PartialResolution bool           `json:"partialResolution"`
	DataSource        string         `json:"dataSource"` // "cilium" | "tetragon"
}

// getNetworkTopology serves the graph from Cilium/Hubble flows. There is no
// Tetragon fallback: kprobe-derived topology could only see pod-initiated
// connections to raw IPs, missed the real source of inbound traffic (the
// kprobe fires after SNAT) and required a TracingPolicy just to collect data.
// When no flows have been observed yet the response is empty and the UI
// explains the Cilium prerequisites.
func getNetworkTopology(k8sStore *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		if k8sStore == nil || !k8sStore.HasCiliumTopoData() {
			writeJSON(w, http.StatusOK, TopologyResponse{
				Nodes:      []TopologyNode{},
				Edges:      []TopologyEdge{},
				DataSource: "cilium",
			})
			return
		}

		// Resolve cluster IPs using TTL-cached lookup
		ipMap := map[string]k8s.IPInfo{}
		partialResolution := false
		if m, err := k8sStore.CachedClusterIPs(r.Context()); err != nil {
			partialResolution = true
		} else {
			ipMap = m
		}

		// Static exposure paths (NodePort/LB/Ingress/hostNetwork) per pod
		exposures := k8sStore.CachedPodExposures(r.Context())
		nodeIPMap := k8sStore.ListNodeIPMap(r.Context())

		writeJSON(w, http.StatusOK, buildCiliumTopology(r.Context(), k8sStore, ipMap, nodeIPMap, exposures, partialResolution))
	}
}

// buildCiliumTopology constructs a topology response from Cilium/Hubble flow data.
// It uses pod names directly from Hubble (no IP lookup needed for known pods).
func buildCiliumTopology(ctx context.Context, k8sStore *k8s.Store, ipMap map[string]k8s.IPInfo, nodeIPMap k8s.NodeIPMap, exposures map[string][]k8s.Exposure, partialResolution bool) TopologyResponse {
	entries := k8sStore.ListCiliumTopoEntries()
	nodeSet := make(map[string]TopologyNode)

	// Flows are buffered for 24h, so a deleted pod would keep its edges for a
	// day. ipMap is already the set of pods that currently exist, so derive the
	// live set from it rather than making another API call.
	livePods := make(map[string]bool, len(ipMap))
	for _, info := range ipMap {
		if info.Kind == "pod" {
			livePods[info.Namespace+"/"+info.Name] = true
		}
	}
	// An empty ipMap means the lookup failed, not that the cluster has no pods.
	// Pruning on that would wipe the whole graph, so only prune when it loaded.
	canPrune := len(livePods) > 0
	gone := func(ns, pod string) bool {
		return canPrune && pod != "" && !livePods[ns+"/"+pod]
	}

	// One edge per (src, dst, blocked) pair — ports are aggregated into a
	// breakdown list instead of fanning out into parallel edges.
	type edgeKey struct {
		src, dst string
		blocked  bool
	}
	type edgeVal struct {
		count      int
		lastSeen   time.Time
		destIP     string
		deniedBy   string
		ports      map[string]int
		l7Type     string
		httpMethod string
		httpURL    string
		httpStatus uint32
		dnsQuery   string
	}
	edgeMap := make(map[edgeKey]*edgeVal)

	resolveID := func(pod, ns, ip string) (string, TopologyNode) {
		if pod != "" {
			id := ns + "/" + pod
			return id, TopologyNode{ID: id, Label: pod, Pod: pod, Namespace: ns, Kind: "pod"}
		}
		if ip == "" {
			return "", TopologyNode{}
		}
		// Skip per-node internal interface IPs (cilium_host etc.) — these are
		// node-local network plumbing, not real endpoints.
		if nodeIPMap.SkipIPs[ip] {
			return "", TopologyNode{}
		}
		// Check if it's a Kubernetes node physical IP → show as "node" kind
		if nodeName, ok := nodeIPMap.IPToName[ip]; ok {
			id := "node:" + ip
			return id, TopologyNode{ID: id, Label: nodeName, Kind: "node", IP: ip}
		}
		// Check if it's in pod CIDR but not a known pod (e.g. cilium_host interface) → skip
		if k8s.IPInCIDRs(ip, nodeIPMap.PodCIDRs) {
			return "", TopologyNode{}
		}
		// Try ipMap for pod IPs. Service ClusterIPs are intentionally not
		// rendered — a VIP is neither a real source nor a real destination.
		if info, ok := ipMap[ip]; ok {
			if info.Kind != "pod" {
				return "", TopologyNode{}
			}
			id := info.Namespace + "/" + info.Name
			return id, TopologyNode{ID: id, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "pod", IP: info.IP}
		}
		id := "ext:" + ip
		return id, TopologyNode{ID: id, Label: ip, Kind: "external", IP: ip}
	}

	staleKeys := make([]string, 0)
	for _, e := range entries {
		// Drop connections whose pod endpoint has since been deleted — the
		// workload is gone, so the edge no longer describes the cluster.
		if gone(e.SrcNs, e.SrcPod) || gone(e.DstNs, e.DstPod) {
			staleKeys = append(staleKeys, e.Key)
			continue
		}
		srcID, srcNode := resolveID(e.SrcPod, e.SrcNs, e.SrcIP)
		if srcID == "" {
			continue // skip: node-internal IP (cilium_host etc.)
		}
		dstID, dstNode := resolveID(e.DstPod, e.DstNs, e.DstIP)
		if dstID == "" {
			continue // skip: node-internal IP
		}

		if _, ok := nodeSet[srcID]; !ok {
			nodeSet[srcID] = srcNode
		}
		if _, ok := nodeSet[dstID]; !ok {
			nodeSet[dstID] = dstNode
		}

		blocked := e.Verdict == "dropped"
		key := edgeKey{srcID, dstID, blocked}
		ev := edgeMap[key]
		if ev == nil {
			ev = &edgeVal{destIP: e.DstIP, ports: make(map[string]int)}
			edgeMap[key] = ev
		}
		ev.count += e.Count
		if e.LastSeen.After(ev.lastSeen) {
			ev.lastSeen = e.LastSeen
		}
		// Name the policy behind a denial. Hubble supplies it for explicit deny
		// rules; for default-deny it has nothing to report, so fall back to the
		// policies that govern this pod in this direction.
		if blocked && ev.deniedBy == "" {
			ev.deniedBy = e.PolicyName
			if ev.deniedBy == "" {
				subjNs, subjPod := e.SrcNs, e.SrcPod
				if e.Direction == "ingress" {
					subjNs, subjPod = e.DstNs, e.DstPod
				}
				ev.deniedBy = k8sStore.AttributePolicyDenial(ctx, subjNs, subjPod, e.Direction)
			}
		}
		if e.Port != "" {
			ev.ports[normalizePort(e.Port)] += e.Count
		}
		if e.L7Type != "" {
			ev.l7Type = e.L7Type
			if e.HTTPMethod != "" {
				ev.httpMethod = e.HTTPMethod
			}
			if e.HTTPURL != "" {
				ev.httpURL = e.HTTPURL
			}
			if e.HTTPStatus > 0 {
				ev.httpStatus = e.HTTPStatus
			}
			if e.DNSQuery != "" {
				ev.dnsQuery = e.DNSQuery
			}
		}
	}

	// One verdict per pair: the most recent one. Blocked used to win outright,
	// which left a denial on the graph after its policy was deleted and — worse —
	// suppressed the allowed edge that replaced it, for as long as the 24h buffer
	// held the stale entry. Recency makes the graph correct itself as soon as
	// traffic flows again.
	type pairTimes struct{ blocked, allowed time.Time }
	pairs := make(map[string]*pairTimes, len(edgeMap))
	for k, ev := range edgeMap {
		id := k.src + "|" + k.dst
		p := pairs[id]
		if p == nil {
			p = &pairTimes{}
			pairs[id] = p
		}
		if k.blocked {
			if ev.lastSeen.After(p.blocked) {
				p.blocked = ev.lastSeen
			}
		} else if ev.lastSeen.After(p.allowed) {
			p.allowed = ev.lastSeen
		}
	}

	// Evict them from the buffer too, so the memory is not held until the TTL
	// and the work is not repeated on every poll.
	if len(staleKeys) > 0 {
		k8sStore.PruneCiliumTopo(staleKeys)
	}

	nodes := make([]TopologyNode, 0, len(nodeSet))
	for _, n := range nodeSet {
		if n.Kind == "pod" {
			if exp := exposures[n.ID]; len(exp) > 0 {
				n.Exposures = exp
			}
		}
		nodes = append(nodes, n)
	}

	edges := make([]TopologyEdge, 0, len(edgeMap))
	for k, ev := range edgeMap {
		p := pairs[k.src+"|"+k.dst]
		// A tie goes to the denial: of the two it is the one worth surfacing.
		showBlocked := !p.blocked.IsZero() && !p.allowed.After(p.blocked)
		if k.blocked != showBlocked {
			continue
		}
		suffix := ""
		if k.blocked {
			suffix = ":blocked"
		}
		edges = append(edges, TopologyEdge{
			ID:         k.src + "->" + k.dst + suffix,
			Source:     k.src,
			Target:     k.dst,
			DestIP:     ev.destIP,
			Count:      ev.count,
			Blocked:    k.blocked,
			DeniedBy:   ev.deniedBy,
			LastSeen:   ev.lastSeen.UTC().Format(time.RFC3339),
			Ports:      portStats(ev.ports),
			L7Type:     ev.l7Type,
			HTTPMethod: ev.httpMethod,
			HTTPURL:    ev.httpURL,
			HTTPStatus: ev.httpStatus,
			DNSQuery:   ev.dnsQuery,
		})
	}

	return TopologyResponse{
		Nodes:             nodes,
		Edges:             edges,
		HasNetworkEvents:  len(edges) > 0,
		PartialResolution: partialResolution,
		DataSource:        "cilium",
	}
}
