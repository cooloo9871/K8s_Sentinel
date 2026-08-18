package k8s

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
	tcpRouteGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tcproutes",
	}
	tlsRouteGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes",
	}
	udpRouteGVR = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "udproutes",
	}
	// Both API groups Traefik has shipped under; a cluster carries one of them.
	traefikGroups = []string{"traefik.io", "traefik.containo.us"}

	contourProxyGVR = schema.GroupVersionResource{
		Group: "projectcontour.io", Version: "v1", Resource: "httpproxies",
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
	istioGatewayGVRs = []schema.GroupVersionResource{
		{Group: "networking.istio.io", Version: "v1", Resource: "gateways"},
		{Group: "networking.istio.io", Version: "v1beta1", Resource: "gateways"},
	}
)

// ExposureHop is one Kubernetes object standing between the outside and the pod.
// Kind and name are separate because the point of listing them is to know which
// object to go and change.
type ExposureHop struct {
	Kind string `json:"kind"` // Gateway, HTTPRoute, Ingress, VirtualService, Backend…
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
	for _, exps := range fresh {
		sortByReach(exps)
	}
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

// servicePort renders the hop every path ends on. Called "Backend" rather than
// "Service" because that is what the manifests call it — backendRefs on a route,
// backend.service on an Ingress — so it matches the field you would go and edit.
func servicePort(ns, name string, port int32) ExposureHop {
	target := qualified(ns, name)
	if port > 0 {
		target = fmt.Sprintf("%s:%d", target, port)
	}
	return ExposureHop{Kind: "Backend", Name: target}
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
	if svcs, err := s.typed.CoreV1().Services("").List(ctx, fromCache); err == nil {
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
	if ings, err := s.typed.NetworkingV1().Ingresses("").List(ctx, fromCache); err == nil {
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
	if pods, err := s.typed.CoreV1().Pods("").List(ctx, fromCache); err == nil {
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
		s.addTraefikExposures(ctx, addForService)
		s.addContourExposures(ctx, addForService)
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

	// All five route kinds share the shape this reads: spec.rules[].backendRefs
	// (TCPRoute and UDPRoute simply have no hostnames).
	for _, rk := range []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{httpRouteGVR, "HTTPRoute"},
		{grpcRouteGVR, "GRPCRoute"},
		{tcpRouteGVR, "TCPRoute"},
		{tlsRouteGVR, "TLSRoute"},
		{udpRouteGVR, "UDPRoute"},
	} {
		list, err := s.client.Resource(rk.gvr).Namespace("").List(ctx, fromCache)
		if err != nil {
			continue // CRD not installed, or no permission — neither is an error here
		}
		routeKind := rk.kind

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
	list, err := s.client.Resource(gatewayGVR).Namespace("").List(ctx, fromCache)
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
	gatewayIndex := s.istioGateways(ctx)
	for _, gvr := range istioVirtualServiceGVRs {
		list, err := s.client.Resource(gvr).Namespace("").List(ctx, fromCache)
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

			vsHosts, _, _ := unstructured.NestedStringSlice(vs.Object, "spec", "hosts")
			// What the outside can actually reach, and on which port — which the
			// VirtualService alone cannot say. Falls back to the VirtualService's
			// own hosts when the Gateway cannot be read.
			reach := istioReach(external, vs.GetNamespace(), vsHosts, gatewayIndex)
			if len(reach) == 0 {
				continue // no Gateway serves these hosts, so nothing is exposed
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
						for _, r := range reach {
							add(ns, svc, Exposure{
								Type:    "istio",
								Address: r.host,
								Detail:  r.detail,
								Hops: []ExposureHop{
									{Kind: "Gateway", Name: r.gateway},
									{Kind: "VirtualService", Name: qualified(vs.GetNamespace(), vs.GetName())},
									servicePort(ns, svc, 0),
								},
							})
						}
					}
				}
			}
		}
		return // the first served version answered; do not double-count
	}
}

// ── Istio Gateway resolution ───────────────────────────────────────────────

// istioServer is one `servers` entry of an Istio Gateway: the hostnames it
// accepts and the port it accepts them on.
type istioServer struct {
	hosts    []string
	port     int64
	protocol string
}

// istioGateways indexes every Istio Gateway by "namespace/name".
//
// A VirtualService says which Gateways carry it but not what those Gateways
// publish, so without reading them there is no way to know the hostname or the
// port the outside actually uses.
func (s *Store) istioGateways(ctx context.Context) map[string][]istioServer {
	out := map[string][]istioServer{}
	for _, gvr := range istioGatewayGVRs {
		list, err := s.client.Resource(gvr).Namespace("").List(ctx, fromCache)
		if err != nil {
			continue
		}
		for _, gw := range list.Items {
			raw, _, _ := unstructured.NestedSlice(gw.Object, "spec", "servers")
			servers := make([]istioServer, 0, len(raw))
			for _, sv := range raw {
				m, ok := sv.(map[string]interface{})
				if !ok {
					continue
				}
				hosts, _, _ := unstructured.NestedStringSlice(m, "hosts")
				port, _, _ := unstructured.NestedInt64(m, "port", "number")
				proto, _, _ := unstructured.NestedString(m, "port", "protocol")
				servers = append(servers, istioServer{hosts: hosts, port: port, protocol: proto})
			}
			out[qualified(gw.GetNamespace(), gw.GetName())] = servers
		}
		return out // the first served version answered; do not double-count
	}
	return out
}

// istioReachEntry is one externally reachable address a VirtualService produces.
type istioReachEntry struct {
	host    string
	detail  string
	gateway string
}

// istioReach works out what the outside can actually reach, by meeting each
// VirtualService host with the hosts its Gateways publish.
//
// A VirtualService's `hosts: ["*"]` does not mean "reachable under any name" —
// it means every host the attached Gateway serves. Reporting it verbatim, which
// is what this used to do, showed a bare "*" for a gateway published at
// "*.test.com", which says nothing about what is exposed.
//
// When a Gateway cannot be read — absent, or no RBAC for it — the
// VirtualService's own hosts are reported rather than dropping the exposure:
// something is still published, and saying so imprecisely beats saying nothing.
func istioReach(gatewayRefs []string, vsNs string, vsHosts []string, gateways map[string][]istioServer) []istioReachEntry {
	if len(vsHosts) == 0 {
		vsHosts = []string{"*"}
	}
	var out []istioReachEntry
	seen := map[string]bool{}
	for _, ref := range gatewayRefs {
		ns, name := splitGatewayRef(ref, vsNs)
		key := qualified(ns, name)
		servers, known := gateways[key]
		if !known {
			for _, h := range vsHosts {
				if id := key + "|" + h; !seen[id] {
					seen[id] = true
					out = append(out, istioReachEntry{host: h, gateway: key})
				}
			}
			continue
		}
		for _, sv := range servers {
			svHosts := sv.hosts
			if len(svHosts) == 0 {
				svHosts = []string{"*"}
			}
			for _, gh := range svHosts {
				for _, vh := range vsHosts {
					host := narrowHost(gh, vh)
					if host == "" {
						continue // the two cannot both match; Istio ignores the route
					}
					detail := ""
					if sv.port > 0 {
						detail = fmt.Sprintf("%s · %d", strings.ToUpper(sv.protocol), sv.port)
						if sv.protocol == "" {
							detail = fmt.Sprintf("port %d", sv.port)
						}
					}
					if id := key + "|" + host + "|" + detail; !seen[id] {
						seen[id] = true
						out = append(out, istioReachEntry{host: host, detail: detail, gateway: key})
					}
				}
			}
		}
	}
	return out
}

// splitGatewayRef resolves a VirtualService's Gateway reference. A bare name
// means the VirtualService's own namespace; "namespace/name" names another; the
// legacy FQDN form is name.namespace.svc.cluster.local.
func splitGatewayRef(ref, defaultNs string) (ns, name string) {
	if before, after, found := strings.Cut(ref, "/"); found {
		return before, after
	}
	if parts := strings.Split(ref, "."); len(parts) > 1 {
		return parts[1], parts[0]
	}
	return defaultNs, ref
}

// narrowHost returns the hostname actually reachable when a VirtualService host
// meets a Gateway server host, or "" when the two cannot both match — in which
// case Istio ignores the route and it exposes nothing.
//
// The more specific of the two wins, which is what Istio itself resolves to.
func narrowHost(gatewayHost, vsHost string) string {
	// A Gateway host may be namespace-qualified — "ns/host", "./host", "*/host".
	if _, after, found := strings.Cut(gatewayHost, "/"); found {
		gatewayHost = after
	}
	switch {
	case gatewayHost == "" || gatewayHost == "*":
		return vsHost
	case vsHost == "" || vsHost == "*":
		return gatewayHost
	case gatewayHost == vsHost:
		return gatewayHost
	case wildcardCovers(gatewayHost, vsHost):
		return vsHost
	case wildcardCovers(vsHost, gatewayHost):
		return gatewayHost
	}
	return ""
}

// wildcardCovers reports whether a "*.suffix" pattern matches the given host.
// Istio's wildcard covers subdomains only, not the bare suffix itself.
func wildcardCovers(pattern, host string) bool {
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	return strings.HasSuffix(host, "."+suffix)
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

// exposureReach ranks how far an entry point reaches, so a pod with several is
// read widest-first. The order matters for an audit: an address on the internet
// is a different problem from a port that first needs access to a node.
// addTraefikExposures resolves Traefik's own route CRDs, which are neither
// Ingress nor Gateway API and carried no badge at all. Hosts come out of the
// rule matches (Host(`...`) / HostSNI(`...`)); a UDP route has no match to
// read.
func (s *Store) addTraefikExposures(ctx context.Context, add func(ns, svc string, e Exposure)) {
	for _, group := range traefikGroups {
		for _, rk := range []struct{ resource, kind string }{
			{"ingressroutes", "IngressRoute"},
			{"ingressroutetcps", "IngressRouteTCP"},
			{"ingressrouteudps", "IngressRouteUDP"},
		} {
			gvr := schema.GroupVersionResource{Group: group, Version: "v1alpha1", Resource: rk.resource}
			list, err := s.client.Resource(gvr).Namespace("").List(ctx, fromCache)
			if err != nil {
				continue // CRD not installed, or no permission
			}
			for _, route := range list.Items {
				routeNs := route.GetNamespace()
				routeHop := ExposureHop{Kind: rk.kind, Name: qualified(routeNs, route.GetName())}
				entryPoints, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "entryPoints")
				detail := strings.Join(entryPoints, ", ")

				rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "routes")
				for _, r := range rules {
					rule, ok := r.(map[string]interface{})
					if !ok {
						continue
					}
					match, _, _ := unstructured.NestedString(rule, "match")
					address := strings.Join(traefikHosts(match), ", ")
					if address == "" {
						address = "*"
					}
					services, _, _ := unstructured.NestedSlice(rule, "services")
					for _, sv := range services {
						svc, ok := sv.(map[string]interface{})
						if !ok {
							continue
						}
						name, _, _ := unstructured.NestedString(svc, "name")
						if name == "" {
							continue
						}
						// Cross-namespace services exist behind a Traefik
						// option; the field is honoured when present.
						ns, _, _ := unstructured.NestedString(svc, "namespace")
						if ns == "" {
							ns = routeNs
						}
						port := intOrStringPort(svc, "port")
						add(ns, name, Exposure{
							Type:    "traefik",
							Address: address,
							Detail:  detail,
							Hops:    []ExposureHop{routeHop, servicePort(ns, name, port)},
						})
					}
				}
			}
		}
	}
}

// traefikHosts pulls the hostnames out of a Traefik rule match: the Host and
// HostSNI functions name what the outside dials.
func traefikHosts(match string) []string {
	var hosts []string
	for _, m := range traefikHostRe.FindAllStringSubmatch(match, -1) {
		hosts = append(hosts, m[1])
	}
	return hosts
}

var traefikHostRe = regexp.MustCompile("Host(?:SNI)?\\(`([^`]+)`")

// addContourExposures resolves Contour's HTTPProxy: the root proxy names the
// FQDN, routes and tcpproxy name the services. Delegated child proxies (the
// includes tree) are listed on their own and carry no fqdn, so their address
// shows as *; following the delegation chain is not attempted.
func (s *Store) addContourExposures(ctx context.Context, add func(ns, svc string, e Exposure)) {
	list, err := s.client.Resource(contourProxyGVR).Namespace("").List(ctx, fromCache)
	if err != nil {
		return // CRD not installed, or no permission
	}
	for _, proxy := range list.Items {
		proxyNs := proxy.GetNamespace()
		proxyHop := ExposureHop{Kind: "HTTPProxy", Name: qualified(proxyNs, proxy.GetName())}
		address, _, _ := unstructured.NestedString(proxy.Object, "spec", "virtualhost", "fqdn")
		if address == "" {
			address = "*"
		}
		detail := ""
		if tls, found, _ := unstructured.NestedMap(proxy.Object, "spec", "virtualhost", "tls"); found && len(tls) > 0 {
			detail = "HTTPS"
		}

		emit := func(services []interface{}) {
			for _, sv := range services {
				svc, ok := sv.(map[string]interface{})
				if !ok {
					continue
				}
				name, _, _ := unstructured.NestedString(svc, "name")
				if name == "" {
					continue
				}
				port := intOrStringPort(svc, "port")
				// HTTPProxy services are same-namespace by design.
				add(proxyNs, name, Exposure{
					Type:    "contour",
					Address: address,
					Detail:  detail,
					Hops:    []ExposureHop{proxyHop, servicePort(proxyNs, name, port)},
				})
			}
		}
		routes, _, _ := unstructured.NestedSlice(proxy.Object, "spec", "routes")
		for _, r := range routes {
			if rule, ok := r.(map[string]interface{}); ok {
				services, _, _ := unstructured.NestedSlice(rule, "services")
				emit(services)
			}
		}
		tcpServices, _, _ := unstructured.NestedSlice(proxy.Object, "spec", "tcpproxy", "services")
		emit(tcpServices)
	}
}

// intOrStringPort reads a port field that manifests write as either a number
// or a numeric string.
func intOrStringPort(obj map[string]interface{}, field string) int32 {
	if n, found, _ := unstructured.NestedInt64(obj, field); found {
		return int32(n)
	}
	if sVal, found, _ := unstructured.NestedString(obj, field); found {
		if n, err := strconv.Atoi(sVal); err == nil {
			return int32(n)
		}
	}
	return 0
}

func exposureReach(kind string) int {
	switch kind {
	case "loadbalancer", "gateway", "istio", "ingress", "traefik", "contour":
		return 0 // routed from wherever the address resolves
	case "externalip":
		return 1 // an address the cluster claims on its own network
	case "nodeport":
		return 2 // needs reachability to some node
	default:
		return 3 // hostPort, hostNetwork — needs a specific node
	}
}

// sortByReach orders in place, keeping detection order within a rank so repeated
// reads do not shuffle.
func sortByReach(exps []Exposure) {
	sort.SliceStable(exps, func(i, j int) bool {
		return exposureReach(exps[i].Type) < exposureReach(exps[j].Type)
	})
}
