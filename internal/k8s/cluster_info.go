package k8s

import (
	"context"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterCIDR holds detected pod and service CIDRs and node IPs for the cluster.
type ClusterCIDR struct {
	PodCIDRs     []string `json:"podCIDRs"`
	ServiceCIDRs []string `json:"serviceCIDRs"`
	NodeIPs      []string `json:"nodeIPs"`
}

// GetClusterCIDR detects pod and service CIDRs from multiple sources.
//
// Pod CIDR detection order:
//  0. cilium-config with ipam cluster-pool (cluster-pool-ipv4-cidr) — Cilium hands out
//     pod addresses itself and ignores --cluster-cidr, which kubeadm sets anyway
//  1. kube-controller-manager pod args (--cluster-cidr)          — Kubernetes IPAM
//  2. cilium-config ConfigMap (ipv4-native-routing-cidr,          — other Cilium setups
//     ipv4-cluster-cidr)
//  3. kube-proxy ConfigMap (clusterCIDR in config body)           — kube-proxy config
//  4. Node spec.podCIDRs fallback                                 — any CNI that sets node podCIDR
//
// Service CIDR detection order:
//  1. kube-apiserver pod args (--service-cluster-ip-range)
//  2. kube-proxy ConfigMap (clusterCIDR comment / service config)
func (s *Store) GetClusterCIDR(ctx context.Context) ClusterCIDR {
	// Empty rather than nil, so the page gets [] and not null.
	result := ClusterCIDR{PodCIDRs: []string{}, ServiceCIDRs: []string{}, NodeIPs: []string{}}

	// ── 0. Cilium's own pool ─────────────────────────────────────────────────
	ciliumCfg, ciliumErr := s.typed.CoreV1().ConfigMaps("kube-system").Get(ctx, "cilium-config", metav1.GetOptions{})
	if ciliumErr == nil {
		result.PodCIDRs = appendUniq(result.PodCIDRs, ciliumPoolCIDRs(ciliumCfg.Data)...)
	}
	fromCilium := len(result.PodCIDRs) > 0

	// ── 1. Control-plane pod args ────────────────────────────────────────────
	for _, component := range []string{"kube-controller-manager", "kube-apiserver"} {
		pods, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "component=" + component,
		})
		if err != nil || len(pods.Items) == 0 {
			continue
		}
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				all := append(container.Command, container.Args...)
				for _, arg := range all {
					if v, ok := trimFlag(arg, "--cluster-cidr"); ok && component == "kube-controller-manager" && !fromCilium {
						result.PodCIDRs = appendUniq(result.PodCIDRs, splitCIDRs(v)...)
					}
					if v, ok := trimFlag(arg, "--service-cluster-ip-range"); ok && component == "kube-apiserver" {
						result.ServiceCIDRs = appendUniq(result.ServiceCIDRs, splitCIDRs(v)...)
					}
				}
			}
		}
	}

	// ── 2. cilium-config ConfigMap ────────────────────────────────────────────
	if len(result.PodCIDRs) == 0 {
		if ciliumErr == nil {
			for _, key := range []string{"cluster-pool-ipv4-cidr", "ipv4-native-routing-cidr", "ipv4-cluster-cidr"} {
				if v := strings.TrimSpace(ciliumCfg.Data[key]); v != "" {
					result.PodCIDRs = appendUniq(result.PodCIDRs, splitCIDRs(v)...)
					break
				}
			}
		}
	}

	// ── 3. kube-proxy ConfigMap ───────────────────────────────────────────────
	// kube-proxy stores its config as a YAML blob inside the ConfigMap data.
	// The clusterCIDR field covers pod CIDR for kube-proxy's own use.
	if len(result.PodCIDRs) == 0 || len(result.ServiceCIDRs) == 0 {
		cm, err := s.typed.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
		if err == nil {
			for _, v := range cm.Data {
				if cidrs := extractKubeProxyCIDR(v); len(cidrs) > 0 && len(result.PodCIDRs) == 0 {
					result.PodCIDRs = appendUniq(result.PodCIDRs, cidrs...)
				}
			}
		}
	}

	// ── 4. Node IPs + pod CIDR fallback ──────────────────────────────────────
	nodes, err := s.typed.CoreV1().Nodes().List(ctx, fromCache)
	if err == nil {
		for _, node := range nodes.Items {
			// Collect InternalIP (and ExternalIP) for every node
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" || addr.Type == "ExternalIP" {
					result.NodeIPs = appendUniq(result.NodeIPs, addr.Address)
				}
			}
			// Pod CIDR fallback
			if len(result.PodCIDRs) == 0 {
				if len(node.Spec.PodCIDRs) > 0 {
					result.PodCIDRs = appendUniq(result.PodCIDRs, node.Spec.PodCIDRs...)
				} else if node.Spec.PodCIDR != "" {
					result.PodCIDRs = appendUniq(result.PodCIDRs, node.Spec.PodCIDR)
				}
			}
		}
	}

	return result
}

// ciliumPoolCIDRs is the pod address range when Cilium allocates from a pool of
// its own, which is its default. The API server's --cluster-cidr says nothing
// about the pods then. In any other mode (kubernetes, a cloud's) the pool keys
// are not what pods get their addresses from, so nothing is returned.
func ciliumPoolCIDRs(cfg map[string]string) []string {
	if mode := strings.TrimSpace(cfg["ipam"]); mode != "" && mode != "cluster-pool" {
		return nil
	}
	var out []string
	for _, key := range []string{"cluster-pool-ipv4-cidr", "cluster-pool-ipv6-cidr"} {
		// Several pools are written with spaces or commas between them.
		out = append(out, splitCIDRs(strings.Join(strings.Fields(cfg[key]), ","))...)
	}
	return out
}

// extractKubeProxyCIDR parses the clusterCIDR value from a kube-proxy config blob.
var reCIDR = regexp.MustCompile(`clusterCIDR:\s*"?([0-9./,\s]+)"?`)

func extractKubeProxyCIDR(configBlob string) []string {
	m := reCIDR.FindStringSubmatch(configBlob)
	if len(m) < 2 {
		return nil
	}
	return splitCIDRs(m[1])
}

func trimFlag(arg, flag string) (string, bool) {
	prefix := flag + "="
	if strings.HasPrefix(arg, prefix) {
		return strings.TrimPrefix(arg, prefix), true
	}
	return "", false
}

func splitCIDRs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func appendUniq(dst []string, items ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range items {
		if !seen[v] {
			seen[v] = true
			dst = append(dst, v)
		}
	}
	return dst
}
