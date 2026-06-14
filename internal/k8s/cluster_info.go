package k8s

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterCIDR holds detected pod and service CIDRs for the cluster.
type ClusterCIDR struct {
	PodCIDRs     []string `json:"podCIDRs"`
	ServiceCIDRs []string `json:"serviceCIDRs"`
}

// GetClusterCIDR attempts to detect the cluster's pod and service CIDRs.
// Detection order:
//  1. kube-controller-manager pod args (--cluster-cidr)
//  2. kube-apiserver pod args (--service-cluster-ip-range)
//  3. Fallback: per-node spec.podCIDRs
func (s *Store) GetClusterCIDR(ctx context.Context) ClusterCIDR {
	result := ClusterCIDR{}

	components := []string{"kube-controller-manager", "kube-apiserver"}
	for _, component := range components {
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

	// Fallback for pod CIDRs: collect from nodes
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
