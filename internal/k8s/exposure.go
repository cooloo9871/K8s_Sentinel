package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// Gateway API. Both are GA in v1; a cluster without the CRDs simply returns
	// an error from List, which is treated as "not installed".
	httpRouteGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes",
	}
	grpcRouteGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes",
	}
	// Istio serves v1 on current releases and v1beta1 on older ones, so the first
	// version that answers wins.
	istioVirtualServiceGVRs = []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"},
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"},
	}
)

// Exposure describes one externally-reachable path to a pod, derived statically
// from K8s API objects (not from observed traffic).
//
// Split into the address and the route rather than one sentence, because the two
// answer different questions and only the first is usually being asked: where do
// I reach this pod from outside, and only then, what carries it there.
type Exposure struct {
	// "nodeport" | "loadbalancer" | "externalip" | "ingress" | "gateway" |
	// "istio" | "hostnetwork" | "hostport"
	Type string `json:"type"`
	// What reaches the pod from outside — a port, an address, a hostname.
	Address string `json:"address"`
	// What routes it there: the object in the path and the Service behind it.
	Via string `json:"via,omitempty"`
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
			// externalIPs is reachable from outside whatever the type says, and it
			// can sit alongside a NodePort or LoadBalancer, so it is its own path
			// rather than a case of the switch. A ClusterIP Service carrying one
			// used to report no exposure at all.
			for _, extIP := range svc.Spec.ExternalIPs {
				for _, p := range svc.Spec.Ports {
					addForService(svc.Namespace, svc.Name, Exposure{
						Type:    "externalip",
						Address: fmt.Sprintf("%s:%d", extIP, p.Port),
						Via:     svc.Name,
					})
				}
			}

			switch svc.Spec.Type {
			case corev1.ServiceTypeNodePort:
				for _, p := range svc.Spec.Ports {
					if p.NodePort > 0 {
						addForService(svc.Namespace, svc.Name, Exposure{
							Type:    "nodeport",
							Address: fmt.Sprintf("any node :%d", p.NodePort),
							Via:     fmt.Sprintf("%s:%d", svc.Name, p.Port),
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
					addr := fmt.Sprintf("%s:%d", lbAddr, p.Port)
					if lbAddr == "" {
						addr = fmt.Sprintf("pending :%d", p.Port)
					}
					addForService(svc.Namespace, svc.Name, Exposure{
						Type: "loadbalancer", Address: addr, Via: svc.Name,
					})
				}
			}
		}
	}

	// 2. Ingress backends — L7 exposure via the ingress controller
	if ings, err := s.typed.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, ing := range ings.Items {
			if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
				addForService(ing.Namespace, db.Service.Name, Exposure{
					Type:    "ingress",
					Address: "any host (default backend)",
					Via:     fmt.Sprintf("%s → %s", ing.Name, db.Service.Name),
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
						Type:    "ingress",
						Address: host + path.Path,
						Via:     fmt.Sprintf("%s → %s", ing.Name, path.Backend.Service.Name),
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
				result[key] = append(result[key], Exposure{
					Type:    "hostnetwork",
					Address: "the node's own IP",
					Via:     "shares the node network namespace",
				})
			}
			for _, c := range p.Spec.Containers {
				for _, port := range c.Ports {
					if port.HostPort > 0 {
						result[key] = append(result[key], Exposure{
							Type:    "hostport",
							Address: fmt.Sprintf("its node :%d", port.HostPort),
							Via:     fmt.Sprintf("%s:%d", c.Name, port.ContainerPort),
						})
					}
				}
			}
		}
	}

	// 4. Gateway API routes and 5. Istio VirtualServices. Both need the dynamic
	// client and both are absent on most clusters, so each is best-effort.
	if s.client != nil {
		s.addGatewayRouteExposures(ctx, addForService)
		s.addIstioExposures(ctx, addForService)
	}

	return result
}

// addGatewayRouteExposures resolves Gateway API routes to the pods behind them.
// A route's backendRefs name Services, which the shared resolution chain turns
// into pods.
func (s *Store) addGatewayRouteExposures(ctx context.Context, add func(ns, svc string, e Exposure)) {
	for _, gvr := range []schema.GroupVersionResource{httpRouteGVR, grpcRouteGVR} {
		list, err := s.client.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil {
			continue // CRD not installed, or no permission — neither is an error here
		}
		for _, route := range list.Items {
			routeNs := route.GetNamespace()
			via := gatewayParents(route)
			hosts, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
			host := "*"
			if len(hosts) > 0 {
				host = strings.Join(hosts, ", ")
			}

			rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
			for _, r := range rules {
				rule, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				refs, _, _ := unstructured.NestedSlice(rule, "backendRefs")
				for _, b := range refs {
					ref, ok := b.(map[string]interface{})
					if !ok {
						continue
					}
					// kind defaults to Service when omitted; anything else is not
					// something this chain can resolve to pods.
					if kind, _, _ := unstructured.NestedString(ref, "kind"); kind != "" && kind != "Service" {
						continue
					}
					name, _, _ := unstructured.NestedString(ref, "name")
					if name == "" {
						continue
					}
					ns, _, _ := unstructured.NestedString(ref, "namespace")
					if ns == "" {
						ns = routeNs
					}
					add(ns, name, Exposure{
						Type:    "gateway",
						Address: host,
						Via:     fmt.Sprintf("%s → %s", via, name),
					})
				}
			}
		}
	}
}

// gatewayParents names the Gateways a route attaches to, for the detail line.
func gatewayParents(route unstructured.Unstructured) string {
	parents, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	var names []string
	for _, p := range parents {
		ref, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if kind, _, _ := unstructured.NestedString(ref, "kind"); kind != "" && kind != "Gateway" {
			continue
		}
		if name, _, _ := unstructured.NestedString(ref, "name"); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return route.GetName()
	}
	return strings.Join(names, ", ")
}

// addIstioExposures resolves Istio VirtualServices to the pods behind them.
//
// Only routes attached to a Gateway count. A VirtualService with no `gateways`
// field, or one listing only the reserved name `mesh`, applies to sidecar
// traffic inside the cluster and exposes nothing externally — counting those
// would mark most of a meshed cluster as externally reachable.
func (s *Store) addIstioExposures(ctx context.Context, add func(ns, svc string, e Exposure)) {
	for _, gvr := range istioVirtualServiceGVRs {
		list, err := s.client.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, vs := range list.Items {
			gateways, _, _ := unstructured.NestedStringSlice(vs.Object, "spec", "gateways")
			var external []string
			for _, g := range gateways {
				if g != "mesh" {
					external = append(external, g)
				}
			}
			if len(external) == 0 {
				continue
			}

			hosts, _, _ := unstructured.NestedStringSlice(vs.Object, "spec", "hosts")
			host := "*"
			if len(hosts) > 0 {
				host = strings.Join(hosts, ", ")
			}
			via := strings.Join(external, ", ")

			for _, section := range []string{"http", "tcp", "tls"} {
				routes, _, _ := unstructured.NestedSlice(vs.Object, "spec", section)
				for _, r := range routes {
					entry, ok := r.(map[string]interface{})
					if !ok {
						continue
					}
					dests, _, _ := unstructured.NestedSlice(entry, "route")
					for _, d := range dests {
						dest, ok := d.(map[string]interface{})
						if !ok {
							continue
						}
						target, _, _ := unstructured.NestedString(dest, "destination", "host")
						svc, ns := splitIstioHost(target, vs.GetNamespace())
						if svc == "" {
							continue
						}
						add(ns, svc, Exposure{
							Type:    "istio",
							Address: host,
							Via:     fmt.Sprintf("%s → %s", via, svc),
						})
					}
				}
			}
		}
		return // the first served version answered; do not double-count
	}
}

// splitIstioHost reads a destination host, which may be a bare Service name or
// any prefix of its FQDN. A host that is neither — an external name reached
// through a ServiceEntry — resolves to no Service and so contributes nothing.
func splitIstioHost(host, defaultNs string) (svc, ns string) {
	host = strings.TrimSpace(host)
	if host == "" || host == "*" {
		return "", ""
	}
	parts := strings.Split(host, ".")
	if len(parts) == 1 {
		return parts[0], defaultNs
	}
	return parts[0], parts[1]
}
