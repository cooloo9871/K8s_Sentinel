package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Exposure describes one externally-reachable path to a pod, derived
// statically from K8s API objects (not from observed traffic).
type Exposure struct {
	Type   string `json:"type"`   // "nodeport" | "loadbalancer" | "ingress" | "hostnetwork" | "hostport"
	Detail string `json:"detail"` // human-readable route, e.g. ":31906 → svc-test:80"
}

// CachedPodExposures returns "namespace/pod" → exposure list, refreshing at
// most every exposureTTL. Best-effort: partial data on API errors.
func (s *Store) CachedPodExposures(ctx context.Context) map[string][]Exposure {
	s.exposureMu.RLock()
	if time.Now().Before(s.exposureExpiry) && s.exposureData != nil {
		d := s.exposureData
		s.exposureMu.RUnlock()
		return d
	}
	s.exposureMu.RUnlock()

	fresh := s.listPodExposures(ctx)
	s.exposureMu.Lock()
	s.exposureData = fresh
	s.exposureExpiry = time.Now().Add(30 * time.Second)
	s.exposureMu.Unlock()
	return fresh
}

func (s *Store) listPodExposures(ctx context.Context) map[string][]Exposure {
	result := make(map[string][]Exposure)
	if s.typed == nil {
		return result
	}

	// Backend resolution chain is always: entry point → Service → Endpoints → Pod.
	svcPods, err := s.ListServicePodNames(ctx)
	if err != nil || svcPods == nil {
		svcPods = map[string][]string{}
	}
	addForService := func(ns, svcName string, exp Exposure) {
		for _, pod := range svcPods[ns+"/"+svcName] {
			key := ns + "/" + pod
			result[key] = append(result[key], exp)
		}
	}

	// 1. NodePort / LoadBalancer services — direct L4 exposure
	if svcs, err := s.typed.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, svc := range svcs.Items {
			switch svc.Spec.Type {
			case corev1.ServiceTypeNodePort:
				for _, p := range svc.Spec.Ports {
					if p.NodePort > 0 {
						addForService(svc.Namespace, svc.Name, Exposure{
							Type:   "nodeport",
							Detail: fmt.Sprintf(":%d → %s:%d", p.NodePort, svc.Name, p.Port),
						})
					}
				}
			case corev1.ServiceTypeLoadBalancer:
				lbAddr := ""
				for _, ing := range svc.Status.LoadBalancer.Ingress {
					if ing.IP != "" {
						lbAddr = ing.IP
						break
					}
					if ing.Hostname != "" {
						lbAddr = ing.Hostname
						break
					}
				}
				for _, p := range svc.Spec.Ports {
					detail := fmt.Sprintf("%s:%d → %s", lbAddr, p.Port, svc.Name)
					if lbAddr == "" {
						detail = fmt.Sprintf("LB :%d → %s (pending)", p.Port, svc.Name)
					}
					addForService(svc.Namespace, svc.Name, Exposure{Type: "loadbalancer", Detail: detail})
				}
			}
		}
	}

	// 2. Ingress backends — L7 exposure via the ingress controller
	if ings, err := s.typed.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, ing := range ings.Items {
			if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
				addForService(ing.Namespace, db.Service.Name, Exposure{
					Type:   "ingress",
					Detail: fmt.Sprintf("%s (default) → %s", ing.Name, db.Service.Name),
				})
			}
			for _, rule := range ing.Spec.Rules {
				host := rule.Host
				if host == "" {
					host = "*"
				}
				if rule.HTTP == nil {
					continue
				}
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service == nil {
						continue
					}
					addForService(ing.Namespace, path.Backend.Service.Name, Exposure{
						Type:   "ingress",
						Detail: fmt.Sprintf("%s%s → %s", host, path.Path, path.Backend.Service.Name),
					})
				}
			}
		}
	}

	// 3. hostNetwork / hostPort pods — reachable directly on the node
	if pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, p := range pods.Items {
			key := p.Namespace + "/" + p.Name
			if p.Spec.HostNetwork {
				result[key] = append(result[key], Exposure{Type: "hostnetwork", Detail: "shares the node network namespace"})
			}
			for _, c := range p.Spec.Containers {
				for _, port := range c.Ports {
					if port.HostPort > 0 {
						result[key] = append(result[key], Exposure{
							Type:   "hostport",
							Detail: fmt.Sprintf("node :%d → %s:%d", port.HostPort, c.Name, port.ContainerPort),
						})
					}
				}
			}
		}
	}

	// Gateway API (HTTPRoute backendRefs → Service → Pods) is intentionally
	// not resolved yet — add a dynamic-client lookup on
	// httproutes.gateway.networking.k8s.io here when Gateway CRDs are in scope.

	return result
}
