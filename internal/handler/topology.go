package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cooloo9871/sentinel/internal/k8s"
	"github.com/cooloo9871/sentinel/internal/security"
)

type TopologyNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"` // "pod" | "service" | "external"
}

type TopologyEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Port   string `json:"port,omitempty"`
	Count  int    `json:"count"`
}

type TopologyResponse struct {
	Nodes            []TopologyNode `json:"nodes"`
	Edges            []TopologyEdge `json:"edges"`
	HasNetworkEvents bool           `json:"hasNetworkEvents"`
	Debug            []string       `json:"debug,omitempty"`
}

func getNetworkTopology(store *security.Store, k8sStore *k8s.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := store.List()

		// Resolve cluster IPs to pod/service names
		ipMap := map[string]k8s.IPInfo{}
		if k8sStore != nil {
			if m, err := k8sStore.ListClusterIPs(r.Context()); err == nil {
				ipMap = m
			}
		}

		type edgeKey struct{ src, dst, port string }
		edgeCounts := make(map[edgeKey]int)
		nodeSet := make(map[string]TopologyNode)
		debugLines := []string{}
		debugEnabled := r.URL.Query().Get("debug") == "1"

		for _, e := range events {
			if e.NetDest == "" || e.Pod == "" {
				continue
			}

			srcID := e.Namespace + "/" + e.Pod
			if _, ok := nodeSet[srcID]; !ok {
				nodeSet[srcID] = TopologyNode{
					ID:        srcID,
					Label:     e.Pod,
					Pod:       e.Pod,
					Namespace: e.Namespace,
					Kind:      "pod",
				}
			}

			// Parse destination: "ip:port", "[::ffff:ip]:port", or just "ip"
			destRaw := e.NetDest
			port := ""
			// Handle IPv6 bracket notation: [addr]:port
			if strings.HasPrefix(destRaw, "[") {
				if end := strings.Index(destRaw, "]"); end != -1 {
					inner := destRaw[1:end]
					// Strip IPv4-mapped IPv6 prefix "::ffff:"
					inner = strings.TrimPrefix(inner, "::ffff:")
					destRaw = inner
					if end+2 < len(e.NetDest) {
						port = e.NetDest[end+2:]
					}
				}
			} else if idx := strings.LastIndex(destRaw, ":"); idx != -1 {
				// Plain IPv4: last colon separates addr and port
				// But check it's not an IPv6 address without brackets
				// (IPv6 without brackets won't have a port — safe to split)
				port = destRaw[idx+1:]
				destRaw = destRaw[:idx]
				// Strip IPv4-mapped IPv6 prefix if present
				destRaw = strings.TrimPrefix(destRaw, "::ffff:")
			}

			if debugEnabled {
				debugLines = append(debugLines, fmt.Sprintf("netDest=%q → destRaw=%q port=%q resolved=%v", e.NetDest, destRaw, port, ipMap[destRaw].Name != ""))
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
					}
				} else {
					dstID = info.Namespace + "/svc/" + info.Name
					dstNode = TopologyNode{
						ID:        dstID,
						Label:     info.Name,
						Pod:       info.Name,
						Namespace: info.Namespace,
						Kind:      "service",
					}
				}
			} else {
				dstID = "ext:" + destRaw
				dstNode = TopologyNode{
					ID:    dstID,
					Label: destRaw,
					Kind:  "external",
				}
			}

			if _, ok := nodeSet[dstID]; !ok {
				nodeSet[dstID] = dstNode
			}

			edgeCounts[edgeKey{srcID, dstID, port}]++
		}

		nodes := make([]TopologyNode, 0, len(nodeSet))
		for _, n := range nodeSet {
			nodes = append(nodes, n)
		}

		edges := make([]TopologyEdge, 0, len(edgeCounts))
		for k, count := range edgeCounts {
			edges = append(edges, TopologyEdge{
				ID:     k.src + "->" + k.dst + ":" + k.port,
				Source: k.src,
				Target: k.dst,
				Port:   k.port,
				Count:  count,
			})
		}

		var dbg []string
		if debugEnabled {
			dbg = debugLines
		}
		writeJSON(w, http.StatusOK, TopologyResponse{
			Nodes:            nodes,
			Edges:            edges,
			HasNetworkEvents: len(edges) > 0,
			Debug:            dbg,
		})
	}
}
