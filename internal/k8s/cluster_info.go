package k8s

import (
	"context"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterCIDR holds detected pod and service CIDRs for the cluster.
type ClusterCIDR struct {
	PodCIDRs     []string `json:"podCIDRs"`
	ServiceCIDRs []string `json:"serviceCIDRs"`
}

// GetClusterCIDR detects pod and service CIDRs from multiple sources.
//
// Pod CIDR detection order:
//  1. kube-controller-manager pod args (--cluster-cidr)          — Kubernetes IPAM
//  2. cilium-config ConfigMap (cluster-pool-ipv4-cidr,            — Cilium cluster-pool IPAM
//     ipv4-native-routing-cidr, ipv4-cluster-cidr)
//  3. kube-proxy ConfigMap (clusterCIDR in config body)           — kube-proxy config
//  4. Node spec.podCIDRs fallback                                 — any CNI that sets node podCIDR
//
// Service CIDR detection order:
//  1. kube-apiserver pod args (--service-cluster-ip-range)
//  2. kube-proxy ConfigMap (clusterCIDR comment / service config)
func (s *Store) GetClusterCIDR(ctx context.Context) ClusterCIDR {
	result := ClusterCIDR{}

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
					if v, ok := trimFlag(arg, "--cluster-cidr"); ok && component == "kube-controller-manager" {
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
		cm, err := s.typed.CoreV1().ConfigMaps("kube-system").Get(ctx, "cilium-config", metav1.GetOptions{})
		if err == nil {
			for _, key := range []string{"cluster-pool-ipv4-cidr", "ipv4-native-routing-cidr", "ipv4-cluster-cidr"} {
				if v := strings.TrimSpace(cm.Data[key]); v != "" {
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

	// ── 4. Node podCIDRs fallback ─────────────────────────────────────────────
	if len(result.PodCIDRs) == 0 {
		nodes, err := s.typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, node := range nodes.Items {
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
