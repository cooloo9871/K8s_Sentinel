package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cooloo9871/sentinel/internal/k8s"
	"github.com/cooloo9871/sentinel/internal/security"
)

type TopologyNode struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Pod         string   `json:"pod"`
	Namespace   string   `json:"namespace"`
	Kind        string   `json:"kind"` // "pod" | "service" | "external" | "node"
	IP          string   `json:"ip,omitempty"`
	BackingPods []string `json:"backingPods,omitempty"` // only set for service nodes
}

type TopologyEdge struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	DestIP  string `json:"destIp,omitempty"`
	Port    string `json:"port,omitempty"`
	Count   int    `json:"count"`
	Blocked bool   `json:"blocked"`
	// L7 fields (populated from Cilium/Hubble data)
	L7Type     string `json:"l7Type,omitempty"`
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPURL    string `json:"httpURL,omitempty"`
	HTTPStatus uint32 `json:"httpStatus,omitempty"`
	DNSQuery   string `json:"dnsQuery,omitempty"`
}

type TopologyResponse struct {
	Nodes             []TopologyNode `json:"nodes"`
	Edges             []TopologyEdge `json:"edges"`
	HasNetworkEvents  bool           `json:"hasNetworkEvents"`
	PartialResolution bool           `json:"partialResolution"`
	DataSource        string         `json:"dataSource"` // "cilium" | "tetragon"
}

func getNetworkTopology(store *security.Store, k8sStore *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		// Resolve cluster IPs using TTL-cached lookup
		ipMap := map[string]k8s.IPInfo{}
		partialResolution := false
		if k8sStore != nil {
			m, err := k8sStore.CachedClusterIPs(r.Context())
			if err != nil {
				partialResolution = true
			} else {
				ipMap = m
			}
		}

		// Fetch service → backing pod names (best-effort; empty map on error)
		svcPods := map[string][]string{}
		if k8sStore != nil {
			if sp, err := k8sStore.ListServicePodNames(r.Context()); err == nil && sp != nil {
				svcPods = sp
			}
		}

		// When Cilium data is available, prefer it over Tetragon topoBuf.
		// Cilium provides pre-NAT IPs, L7 metadata, and all flows regardless of TracingPolicy.
		if k8sStore != nil && k8sStore.HasCiliumTopoData() {
			nodeIPMap := k8sStore.ListNodeIPMap(r.Context())
			writeJSON(w, http.StatusOK, buildCiliumTopology(k8sStore, ipMap, svcPods, nodeIPMap, partialResolution))
			return
		}

		events := store.ListTopologyEvents()

		type edgeKey struct {
			src, dst, destIP, port string
			blocked                bool
		}
		edgeCounts := make(map[edgeKey]int)
		nodeSet := make(map[string]TopologyNode)

		for _, e := range events {
			if e.Pod == "" {
				continue
			}

			// Source is always the pod initiating the connection
			srcID := e.Namespace + "/" + e.Pod
			if _, ok := nodeSet[srcID]; !ok {
				// NetSrc is "ip:port"; strip the port before ipMap lookup
				srcAddrRaw := e.NetSrc
				if strings.HasPrefix(srcAddrRaw, "[") {
					if end := strings.Index(srcAddrRaw, "]"); end != -1 {
						srcAddrRaw = strings.TrimPrefix(srcAddrRaw[1:end], "::ffff:")
					}
				} else if idx := strings.LastIndex(srcAddrRaw, ":"); idx != -1 {
					srcAddrRaw = strings.TrimPrefix(srcAddrRaw[:idx], "::ffff:")
				}
				srcIP := ""
				if info, ok2 := ipMap[srcAddrRaw]; ok2 {
					srcIP = info.IP
				}
				nodeSet[srcID] = TopologyNode{
					ID:        srcID,
					Label:     e.Pod,
					Pod:       e.Pod,
					Namespace: e.Namespace,
					Kind:      "pod",
					IP:        srcIP,
				}
			}

			// Parse destination: "ip:port", "[::ffff:ip]:port", or just "ip"
			destRaw := e.NetDest
			port := ""
			if strings.HasPrefix(destRaw, "[") {
				if end := strings.Index(destRaw, "]"); end != -1 {
					inner := destRaw[1:end]
					inner = strings.TrimPrefix(inner, "::ffff:")
					destRaw = inner
					if end+2 < len(e.NetDest) {
						port = e.NetDest[end+2:]
					}
				}
			} else if idx := strings.LastIndex(destRaw, ":"); idx != -1 {
				port = destRaw[idx+1:]
				destRaw = destRaw[:idx]
				destRaw = strings.TrimPrefix(destRaw, "::ffff:")
			}

			// Try to resolve destination IP to pod/service
			var dstID string
			var dstNode TopologyNode
			if info, ok := ipMap[destRaw]; ok {
				if info.Kind == "pod" {
					dstID = info.Namespace + "/" + info.Name
					dstNode = TopologyNode{
						ID:        dstID,
						Label:     info.Name,
						Pod:       info.Name,
						Namespace: info.Namespace,
						Kind:      "pod",
						IP:        info.IP,
					}
				} else {
					dstID = info.Namespace + "/svc/" + info.Name
					dstNode = TopologyNode{
						ID:        dstID,
						Label:     info.Name,
						Pod:       info.Name,
						Namespace: info.Namespace,
						Kind:      "service",
						IP:        info.IP,
					}
				}
			} else {
				dstID = "ext:" + destRaw
				dstNode = TopologyNode{
					ID:    dstID,
					Label: destRaw,
					Kind:  "external",
					IP:    destRaw,
				}
			}

			if _, ok := nodeSet[dstID]; !ok {
				nodeSet[dstID] = dstNode
			}

			blocked := e.Action == "kill"
			edgeCounts[edgeKey{srcID, dstID, destRaw, port, blocked}]++
		}

		// Attach backing pod names to service nodes
		for id, n := range nodeSet {
			if n.Kind == "service" {
				key := n.Namespace + "/" + n.Label
				if pods := svcPods[key]; len(pods) > 0 {
					n.BackingPods = pods
					nodeSet[id] = n
				}
			}
		}

		nodes := make([]TopologyNode, 0, len(nodeSet))
		for _, n := range nodeSet {
			nodes = append(nodes, n)
		}

		edges := make([]TopologyEdge, 0, len(edgeCounts))
		for k, count := range edgeCounts {
			suffix := ""
			if k.blocked {
				suffix = ":blocked"
			}
			edges = append(edges, TopologyEdge{
				ID:      k.src + "->" + k.dst + ":" + k.destIP + ":" + k.port + suffix,
				Source:  k.src,
				Target:  k.dst,
				DestIP:  k.destIP,
				Port:    k.port,
				Count:   count,
				Blocked: k.blocked,
			})
		}

		writeJSON(w, http.StatusOK, TopologyResponse{
			Nodes:             nodes,
			Edges:             edges,
			HasNetworkEvents:  len(edges) > 0,
			PartialResolution: partialResolution,
			DataSource:        "tetragon",
		})
	}
}

// buildCiliumTopology constructs a topology response from Cilium/Hubble flow data.
// It uses pod names directly from Hubble (no IP lookup needed for known pods).
func buildCiliumTopology(k8sStore *k8s.Store, ipMap map[string]k8s.IPInfo, svcPods map[string][]string, nodeIPMap k8s.NodeIPMap, partialResolution bool) TopologyResponse {
	entries := k8sStore.ListCiliumTopoEntries()
	nodeSet := make(map[string]TopologyNode)

	type edgeKey struct {
		src, dst, port string
		blocked        bool
	}
	type edgeVal struct {
		count      int
		destIP     string
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
		// Check if it's a Kubernetes node physical IP → show as "node" kind
		if nodeName, ok := nodeIPMap.IPToName[ip]; ok {
			id := "node:" + ip
			return id, TopologyNode{ID: id, Label: nodeName, Kind: "node", IP: ip}
		}
		// Check if it's in pod CIDR but not a known pod (e.g. cilium_host interface) → skip
		if k8s.IPInCIDRs(ip, nodeIPMap.PodCIDRs) {
			return "", TopologyNode{}
		}
		// Try ipMap for pod/service IPs
		if info, ok := ipMap[ip]; ok {
			if info.Kind == "pod" {
				id := info.Namespace + "/" + info.Name
				return id, TopologyNode{ID: id, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "pod", IP: info.IP}
			}
			id := info.Namespace + "/svc/" + info.Name
			return id, TopologyNode{ID: id, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "service", IP: info.IP}
		}
		id := "ext:" + ip
		return id, TopologyNode{ID: id, Label: ip, Kind: "external", IP: ip}
	}

	for _, e := range entries {
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

		// Attach backing pods to service nodes
		if dstNode.Kind == "service" {
			if n, ok := nodeSet[dstID]; ok && len(n.BackingPods) == 0 {
				if pods := svcPods[dstNode.Namespace+"/"+dstNode.Label]; len(pods) > 0 {
					n.BackingPods = pods
					nodeSet[dstID] = n
				}
			}
		}

		blocked := e.Verdict == "dropped"
		key := edgeKey{srcID, dstID, e.Port, blocked}
		ev := edgeMap[key]
		if ev == nil {
			ev = &edgeVal{destIP: e.DstIP}
			edgeMap[key] = ev
		}
		ev.count += e.Count
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

	// Dedup: blocked supersedes allowed for same src→dst→port
	blockedKeys := make(map[string]bool)
	for k := range edgeMap {
		if k.blocked {
			blockedKeys[k.src+"|"+k.dst+"|"+k.port] = true
		}
	}

	nodes := make([]TopologyNode, 0, len(nodeSet))
	for _, n := range nodeSet {
		nodes = append(nodes, n)
	}

	edges := make([]TopologyEdge, 0, len(edgeMap))
	for k, ev := range edgeMap {
		if !k.blocked && blockedKeys[k.src+"|"+k.dst+"|"+k.port] {
			continue // skip allowed when blocked exists
		}
		suffix := ""
		if k.blocked {
			suffix = ":blocked"
		}
		l7suffix := ""
		if ev.l7Type != "" {
			l7suffix = ":" + ev.l7Type
		}
		edges = append(edges, TopologyEdge{
			ID:         fmt.Sprintf("%s->%s:%s:%s%s%s", k.src, k.dst, ev.destIP, k.port, suffix, l7suffix),
			Source:     k.src,
			Target:     k.dst,
			DestIP:     ev.destIP,
			Port:       k.port,
			Count:      ev.count,
			Blocked:    k.blocked,
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
