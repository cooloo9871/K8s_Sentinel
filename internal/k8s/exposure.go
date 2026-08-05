package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
	gatewayGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways",
	}
	// Istio serves v1 on current releases and v1beta1 on older ones, so the first
	// version that answers wins.
	istioVirtualServiceGVRs = []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"},
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"},
	}
)

// ExposureHop is one Kubernetes object standing between the outside and the pod.
// Kind and name are separate because the point of listing them is to know which
// object to go and change.
type ExposureHop struct {
	Kind string `json:"kind"` // Gateway, HTTPRoute, Ingress, VirtualService, Service…
	Name string `json:"name"` // "namespace/name", with a port where one applies
}

// Exposure describes one externally-reachable path to a pod, derived statically
// from K8s API objects (not from observed traffic).
//
// The path is kept as a chain rather than flattened into a sentence: an operator
// reading it wants the address first, and then the objects that carry traffic
// there, because those are what they would edit to close it.
type Exposure struct {
	// "nodeport" | "loadbalancer" | "externalip" | "ingress" | "gateway" |
	// "istio" | "hostnetwork" | "hostport"
	Type string `json:"type"`
	// What reaches the pod from outside — a port, an address, a hostname.
	Address string `json:"address"`
	// The protocol and port behind that address, where they are knowable.
	Detail string `json:"detail,omitempty"`
	// The objects in the path, outermost first, ending at the Service.
	Hops []ExposureHop `json:"hops,omitempty"`
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

// qualified renders an object as an operator would look it up.
func qualified(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

// servicePort renders the Service hop, which is where every path ends.
func servicePort(ns, name string, port int32) ExposureHop {
	target := qualified(ns, name)
	if port > 0 {
		target = fmt.Sprintf("%s:%d", target, port)
	}
	return ExposureHop{Kind: "Service", Name: target}
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
						Detail:  fmt.Sprintf("%s · %d", portProtocol(p), p.Port),
						Hops:    []ExposureHop{servicePort(svc.Namespace, svc.Name, p.Port)},
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
							Detail:  fmt.Sprintf("%s · %d → %d", portProtocol(p), p.NodePort, p.Port),
							Hops:    []ExposureHop{servicePort(svc.Namespace, svc.Name, p.Port)},
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
						Type:    "loadbalancer",
						Address: addr,
						Detail:  fmt.Sprintf("%s · %d", portProtocol(p), p.Port),
						Hops:    []ExposureHop{servicePort(svc.Namespace, svc.Name, p.Port)},
					})
				}
			}
		}
	}

	// 2. Ingress backends — L7 exposure via the ingress controller
	if ings, err := s.typed.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, ing := range ings.Items {
			ingHop := ExposureHop{Kind: "Ingress", Name: qualified(ing.Namespace, ing.Name)}

			if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
				addForService(ing.Namespace, db.Service.Name, Exposure{
					Type:    "ingress",
					Address: "any host (default backend)",
					Detail:  ingressScheme(ing, ""),
					Hops: []ExposureHop{ingHop,
						servicePort(ing.Namespace, db.Service.Name, backendPort(db.Service.Port))},
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
						Detail:  ingressScheme(ing, rule.Host),
						Hops: []ExposureHop{ingHop,
							servicePort(ing.Namespace, path.Backend.Service.Name,
								backendPort(path.Backend.Service.Port))},
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
					Detail:  "shares the node network namespace",
				})
			}
			for _, c := range p.Spec.Containers {
				for _, port := range c.Ports {
					if port.HostPort > 0 {
						result[key] = append(result[key], Exposure{
							Type:    "hostport",
							Address: fmt.Sprintf("its node :%d", port.HostPort),
							Detail:  fmt.Sprintf("%s · %d → %d", hostPortProtocol(port), port.HostPort, port.ContainerPort),
							Hops: []ExposureHop{{
								Kind: "Container",
								Name: fmt.Sprintf("%s:%d", c.Name, port.ContainerPort),
							}},
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
	// Listed once and indexed, so naming the Gateway and reading its listener
	// costs one call rather than one per route.
	listeners := s.gatewayListeners(ctx)

	for _, gvr := range []schema.GroupVersionResource{httpRouteGVR, grpcRouteGVR} {
		list, err := s.client.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil {
			continue // CRD not installed, or no permission — neither is an error here
		}
		routeKind := "HTTPRoute"
		if gvr == grpcRouteGVR {
			routeKind = "GRPCRoute"
		}

		for _, route := range list.Items {
			routeNs := route.GetNamespace()
			hosts, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
			host := "*"
			if len(hosts) > 0 {
				host = strings.Join(hosts, ", ")
			}

			// A parentRef without a namespace means the route's own.
			gwHops, detail := gatewayHops(route, routeNs, listeners)
			routeHop := ExposureHop{Kind: routeKind, Name: qualified(routeNs, route.GetName())}

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
					port, _, _ := unstructured.NestedInt64(ref, "port")
					add(ns, name, Exposure{
						Type:    "gateway",
						Address: host,
						Detail:  detail,
						Hops: append(append([]ExposureHop{}, gwHops...),
							routeHop, servicePort(ns, name, int32(port))),
					})
				}
			}
		}
	}
}

// gatewayHops names the Gateways a route attaches to, and reads the scheme from
// the listener it targets — which is the part a route alone cannot say.
func gatewayHops(
	route unstructured.Unstructured, routeNs string, listeners map[string]string,
) ([]ExposureHop, string) {
	parents, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	var hops []ExposureHop
	detail := ""
	for _, p := range parents {
		ref, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if kind, _, _ := unstructured.NestedString(ref, "kind"); kind != "" && kind != "Gateway" {
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
		key := ns + "/" + name
		hops = append(hops, ExposureHop{Kind: "Gateway", Name: key})
		if section, _, _ := unstructured.NestedString(ref, "sectionName"); section != "" {
			if d := listeners[key+"/"+section]; d != "" {
				detail = d
			}
		}
		if detail == "" {
			detail = listeners[key]
		}
	}
	return hops, detail
}

// gatewayListeners indexes every Gateway's listeners as "protocol · port", both
// per named section and once for the Gateway as a whole, so a route that does not
// name a section still gets an answer.
func (s *Store) gatewayListeners(ctx context.Context) map[string]string {
	out := map[string]string{}
	list, err := s.client.Resource(gatewayGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return out
	}
	for _, gw := range list.Items {
		key := gw.GetNamespace() + "/" + gw.GetName()
		items, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
		for _, l := range items {
			listener, ok := l.(map[string]interface{})
			if !ok {
				continue
			}
			proto, _, _ := unstructured.NestedString(listener, "protocol")
			port, _, _ := unstructured.NestedInt64(listener, "port")
			if proto == "" || port == 0 {
				continue
			}
			detail := fmt.Sprintf("%s · %d", proto, port)
			if name, _, _ := unstructured.NestedString(listener, "name"); name != "" {
				out[key+"/"+name] = detail
			}
			// The first listener stands for the Gateway when no section is named.
			if _, seen := out[key]; !seen {
				out[key] = detail
			}
		}
	}
	return out
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
						hops := make([]ExposureHop, 0, len(external)+2)
						for _, g := range external {
							hops = append(hops, ExposureHop{Kind: "Gateway", Name: g})
						}
						hops = append(hops,
							ExposureHop{Kind: "VirtualService", Name: qualified(vs.GetNamespace(), vs.GetName())},
							servicePort(ns, svc, 0))
						add(ns, svc, Exposure{
							Type:    "istio",
							Address: host,
							Hops:    hops,
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

// portProtocol names a Service port's protocol, which defaults to TCP.
func portProtocol(p corev1.ServicePort) string {
	if p.Protocol == "" {
		return "TCP"
	}
	return string(p.Protocol)
}

func hostPortProtocol(p corev1.ContainerPort) string {
	if p.Protocol == "" {
		return "TCP"
	}
	return string(p.Protocol)
}

// backendPort takes whichever of the two forms an Ingress backend port uses.
// A named port cannot be resolved without the Service, and reporting no port is
// better than reporting a name where a number is expected.
func backendPort(p networkingv1.ServiceBackendPort) int32 {
	return p.Number
}

// ingressScheme reports HTTPS when the host is covered by a TLS block, which is
// the only place an Ingress says so.
func ingressScheme(ing networkingv1.Ingress, host string) string {
	for _, tls := range ing.Spec.TLS {
		if len(tls.Hosts) == 0 {
			return "HTTPS · 443"
		}
		for _, h := range tls.Hosts {
			if h == host {
				return "HTTPS · 443"
			}
		}
	}
	return "HTTP · 80"
}
