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

			inbound := e.Function == "inet_csk_accept"

			if !inbound {
				// ── Outbound (tcp_connect): pod → destination ──────────────────
				srcID := e.Namespace + "/" + e.Pod
				if _, ok := nodeSet[srcID]; !ok {
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

				destRaw := e.NetDest
				port := ""
				if strings.HasPrefix(destRaw, "[") {
					if end := strings.Index(destRaw, "]"); end != -1 {
						inner := strings.TrimPrefix(destRaw[1:end], "::ffff:")
						destRaw = inner
						if end+2 < len(e.NetDest) {
							port = e.NetDest[end+2:]
						}
					}
				} else if idx := strings.LastIndex(destRaw, ":"); idx != -1 {
					port = destRaw[idx+1:]
					destRaw = strings.TrimPrefix(destRaw[:idx], "::ffff:")
				}

				var dstID string
				var dstNode TopologyNode
				if info, ok := ipMap[destRaw]; ok {
					if info.Kind == "pod" {
						dstID = info.Namespace + "/" + info.Name
						dstNode = TopologyNode{ID: dstID, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "pod", IP: info.IP}
					} else {
						dstID = info.Namespace + "/svc/" + info.Name
						dstNode = TopologyNode{ID: dstID, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "service", IP: info.IP}
					}
				} else {
					dstID = "ext:" + destRaw
					dstNode = TopologyNode{ID: dstID, Label: destRaw, Kind: "external", IP: destRaw}
				}
				if _, ok := nodeSet[dstID]; !ok {
					nodeSet[dstID] = dstNode
				}
				blocked := e.Action == "kill"
				edgeCounts[edgeKey{srcID, dstID, destRaw, port, blocked}]++
				continue
			}

			// ── Inbound (inet_csk_accept): client → accepting pod ──────────────
			// e.NetDest = remote client IP:ephemeralPort
			// e.NetSrc  = local pod IP:servicePort
			// Destination node = the accepting pod
			dstID := e.Namespace + "/" + e.Pod
			if _, ok := nodeSet[dstID]; !ok {
				nodeSet[dstID] = TopologyNode{
					ID:        dstID,
					Label:     e.Pod,
					Pod:       e.Pod,
					Namespace: e.Namespace,
					Kind:      "pod",
				}
			}

			// Source node = the remote client (strip ephemeral port)
			clientRaw := e.NetDest
			if strings.HasPrefix(clientRaw, "[") {
				if end := strings.Index(clientRaw, "]"); end != -1 {
					clientRaw = strings.TrimPrefix(clientRaw[1:end], "::ffff:")
				}
			} else if idx := strings.LastIndex(clientRaw, ":"); idx != -1 {
				clientRaw = strings.TrimPrefix(clientRaw[:idx], "::ffff:")
			}

			// Service port = the local port the pod is listening on
			svcPort := ""
			if idx := strings.LastIndex(e.NetSrc, ":"); idx != -1 {
				svcPort = e.NetSrc[idx+1:]
			}

			var srcID string
			if info, ok := ipMap[clientRaw]; ok {
				if info.Kind == "pod" {
					srcID = info.Namespace + "/" + info.Name
					if _, ok2 := nodeSet[srcID]; !ok2 {
						nodeSet[srcID] = TopologyNode{ID: srcID, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "pod", IP: info.IP}
					}
				} else {
					srcID = info.Namespace + "/svc/" + info.Name
					if _, ok2 := nodeSet[srcID]; !ok2 {
						nodeSet[srcID] = TopologyNode{ID: srcID, Label: info.Name, Pod: info.Name, Namespace: info.Namespace, Kind: "service", IP: info.IP}
					}
				}
			} else {
				srcID = "ext:" + clientRaw
				if _, ok2 := nodeSet[srcID]; !ok2 {
					nodeSet[srcID] = TopologyNode{ID: srcID, Label: clientRaw, Kind: "external", IP: clientRaw}
				}
			}

			blocked := e.Action == "kill"
			edgeCounts[edgeKey{srcID, dstID, clientRaw, svcPort, blocked}]++
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
