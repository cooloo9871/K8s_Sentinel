package handler

import (
	"net/http"
	"strings"

	"github.com/cooloo9871/sentinel/internal/security"
)

type TopologyNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"` // "pod" | "external"
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
}

func getNetworkTopology(store *security.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := store.List()

		// Filter to only network events
		type edgeKey struct{ src, dst, port string }
		edgeCounts := make(map[edgeKey]int)
		nodeSet := make(map[string]TopologyNode)

		for _, e := range events {
			if e.NetDest == "" {
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

			// Parse destination: "ip:port" or just "ip"
			dest := e.NetDest
			port := ""
			if idx := strings.LastIndex(dest, ":"); idx != -1 {
				port = dest[idx+1:]
				dest = dest[:idx]
			}

			// Determine if destination is a pod (cluster IP) or external
			dstID := "ext:" + dest
			if _, ok := nodeSet[dstID]; !ok {
				nodeSet[dstID] = TopologyNode{
					ID:    dstID,
					Label: dest,
					Kind:  "external",
				}
			}

			edgeCounts[edgeKey{srcID, dstID, port}]++
		}

		nodes := make([]TopologyNode, 0, len(nodeSet))
		for _, n := range nodeSet {
			nodes = append(nodes, n)
		}

		edges := make([]TopologyEdge, 0, len(edgeCounts))
		i := 0
		for k, count := range edgeCounts {
			edges = append(edges, TopologyEdge{
				ID:     k.src + "->" + k.dst + ":" + k.port,
				Source: k.src,
				Target: k.dst,
				Port:   k.port,
				Count:  count,
			})
			i++
		}

		writeJSON(w, http.StatusOK, TopologyResponse{
			Nodes:            nodes,
			Edges:            edges,
			HasNetworkEvents: len(edges) > 0,
		})
	}
}
