package handler

import (
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
	Kind        string   `json:"kind"` // "pod" | "service" | "external"
	IP          string   `json:"ip,omitempty"`
	BackingPods []string `json:"backingPods,omitempty"` // only set for service nodes
}

type TopologyEdge struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	DestIP  string `json:"destIp,omitempty"`  // raw destination IP
	Port    string `json:"port,omitempty"`
	Count   int    `json:"count"`
	Blocked bool   `json:"blocked"` // true when action="kill"
}

type TopologyResponse struct {
	Nodes            []TopologyNode `json:"nodes"`
	Edges            []TopologyEdge `json:"edges"`
	HasNetworkEvents bool           `json:"hasNetworkEvents"`
	PartialResolution bool          `json:"partialResolution"` // true when IP→name lookup failed
}

func getNetworkTopology(store *security.Store, k8sStore *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := store.ListTopologyEvents()

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

		type edgeKey struct{ src, dst, destIP, port string; blocked bool }
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
		})
	}
}
