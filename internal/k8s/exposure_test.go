package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestSplitIstioHost(t *testing.T) {
	cases := []struct{ host, defaultNs, svc, ns string }{
		// A bare name means the VirtualService's own namespace.
		{"reviews", "prod", "reviews", "prod"},
		// Any prefix of the FQDN carries the namespace as its second label.
		{"reviews.staging", "prod", "reviews", "staging"},
		{"reviews.staging.svc.cluster.local", "prod", "reviews", "staging"},
		// An external name reached through a ServiceEntry parses to something
		// that matches no Service, which is how it contributes nothing.
		{"api.example.com", "prod", "api", "example"},
		{"*", "prod", "", ""},
		{"", "prod", "", ""},
	}
	for _, c := range cases {
		svc, ns := splitIstioHost(c.host, c.defaultNs)
		if svc != c.svc || ns != c.ns {
			t.Errorf("splitIstioHost(%q, %q) = %q/%q, want %q/%q",
				c.host, c.defaultNs, svc, ns, c.svc, c.ns)
		}
	}
}

// routeClient builds a dynamic client that serves the CRDs the exposure lookup
// asks for, so an empty cluster is distinguishable from a missing CRD.
func routeClient(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			httpRouteGVR:               "HTTPRouteList",
			gatewayGVR:                 "GatewayList",
			grpcRouteGVR:               "GRPCRouteList",
			istioVirtualServiceGVRs[0]: "VirtualServiceList",
			istioVirtualServiceGVRs[1]: "VirtualServiceList",
			cnpGVR:                     "CiliumNetworkPolicyList",
			ccnpGVR:                    "CiliumClusterwideNetworkPolicyList",
		},
		objs...,
	)
}

// withGateway seeds a Gateway through the resource interface rather than the
// constructor. The fake client places seeded objects by guessing the resource
// from the kind, and that guess turns a kind ending in "y" into "ies" — so
// "Gateway" lands under "gatewaies" and a List on "gateways" finds nothing.
// The real API server serves "gateways", which the CRD names explicitly.
func withGateway(t *testing.T, c *dynfake.FakeDynamicClient, gw *unstructured.Unstructured) *dynfake.FakeDynamicClient {
	t.Helper()
	_, err := c.Resource(gatewayGVR).Namespace(gw.GetNamespace()).
		Create(context.Background(), gw, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seeding the Gateway: %v", err)
	}
	return c
}

func httpRoute(ns, name, gateway, host, backendNs, backend string) *unstructured.Unstructured {
	ref := map[string]interface{}{"name": backend}
	if backendNs != "" {
		ref["namespace"] = backendNs
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]interface{}{"name": name, "namespace": ns},
		"spec": map[string]interface{}{
			"parentRefs": []interface{}{map[string]interface{}{"name": gateway}},
			"hostnames":  []interface{}{host},
			"rules": []interface{}{map[string]interface{}{
				"backendRefs": []interface{}{ref},
			}},
		},
	}}
}

func virtualService(ns, name string, gateways []interface{}, destHost string) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"hosts": []interface{}{"shop.example.com"},
		"http": []interface{}{map[string]interface{}{
			"route": []interface{}{map[string]interface{}{
				"destination": map[string]interface{}{"host": destHost},
			}},
		}},
	}
	if gateways != nil {
		spec["gateways"] = gateways
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.istio.io/v1",
		"kind":       "VirtualService",
		"metadata":   map[string]interface{}{"name": name, "namespace": ns},
		"spec":       spec,
	}}
}

// A Service with an EndpointSlice naming the pod, which is the chain every
// exposure type resolves through.
func servedPod(ns, svc, pod string) []runtime.Object {
	return append(
		[]runtime.Object{&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: svc, Namespace: ns},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
		}},
		endpointSlice(ns, svc, svc+"-abc", pod),
	)
}

func endpointSlice(ns, svc, name string, pods ...string) runtime.Object {
	eps := make([]discoveryv1.Endpoint, 0, len(pods))
	for _, p := range pods {
		eps = append(eps, discoveryv1.Endpoint{
			Addresses: []string{"10.0.0.1"},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: p, Namespace: ns},
		})
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
		Endpoints: eps,
	}
}

func exposureTypes(exps []Exposure) []string {
	out := make([]string, 0, len(exps))
	for _, e := range exps {
		out = append(out, e.Type)
	}
	return out
}

func TestGatewayAPIRouteExposesItsBackendPods(t *testing.T) {
	s := &Store{
		typed:  k8sfake.NewSimpleClientset(servedPod("shop", "web", "web-1")...),
		client: routeClient(httpRoute("shop", "web-route", "public-gw", "shop.example.com", "", "web")),
	}

	exps := s.listPodExposures(context.Background())["shop/web-1"]
	if len(exps) != 1 || exps[0].Type != "gateway" {
		t.Fatalf("got %v, want one gateway exposure", exposureTypes(exps))
	}
	// The detail has to name the Gateway, or an audit cannot tell which front
	// door reaches this pod.
	if exps[0].Address != "shop.example.com" {
		t.Errorf("address = %q, want the hostname reached from outside", exps[0].Address)
	}
	// The chain has to name each object, since those are what an operator edits.
	want := []ExposureHop{
		{Kind: "Gateway", Name: "shop/public-gw"},
		{Kind: "HTTPRoute", Name: "shop/web-route"},
		{Kind: "Backend", Name: "shop/web"},
	}
	if len(exps[0].Hops) != len(want) {
		t.Fatalf("hops = %+v, want %+v", exps[0].Hops, want)
	}
	for i := range want {
		if exps[0].Hops[i] != want[i] {
			t.Errorf("hop %d = %+v, want %+v", i, exps[0].Hops[i], want[i])
		}
	}
}

// backendRefs may name another namespace, which is the whole point of a shared
// Gateway. Defaulting to the route's namespace would attribute it to nothing.
func TestGatewayAPIRouteFollowsACrossNamespaceBackend(t *testing.T) {
	s := &Store{
		typed:  k8sfake.NewSimpleClientset(servedPod("shop", "web", "web-1")...),
		client: routeClient(httpRoute("gateways", "web-route", "public-gw", "shop.example.com", "shop", "web")),
	}

	if exps := s.listPodExposures(context.Background())["shop/web-1"]; len(exps) != 1 {
		t.Errorf("got %v, want the backend in another namespace to be reached", exposureTypes(exps))
	}
}

func TestIstioVirtualServiceOnAGatewayExposesItsDestination(t *testing.T) {
	s := &Store{
		typed:  k8sfake.NewSimpleClientset(servedPod("shop", "reviews", "reviews-1")...),
		client: routeClient(virtualService("shop", "reviews-vs", []interface{}{"istio-system/public"}, "reviews")),
	}

	exps := s.listPodExposures(context.Background())["shop/reviews-1"]
	if len(exps) != 1 || exps[0].Type != "istio" {
		t.Fatalf("got %v, want one istio exposure", exposureTypes(exps))
	}
}

// A VirtualService with no gateways, or only the reserved `mesh`, governs
// sidecar traffic inside the cluster. Counting those would mark most of a meshed
// cluster as externally reachable.
func TestIstioMeshOnlyVirtualServiceIsNotAnExposure(t *testing.T) {
	for _, gateways := range []([]interface{}){nil, {"mesh"}} {
		s := &Store{
			typed:  k8sfake.NewSimpleClientset(servedPod("shop", "reviews", "reviews-1")...),
			client: routeClient(virtualService("shop", "reviews-vs", gateways, "reviews")),
		}
		if exps := s.listPodExposures(context.Background())["shop/reviews-1"]; len(exps) != 0 {
			t.Errorf("gateways=%v produced %v, want none", gateways, exposureTypes(exps))
		}
	}
}

// A destination naming an external host resolves to no Service, so it adds
// nothing rather than inventing an exposure.
func TestIstioExternalDestinationAddsNothing(t *testing.T) {
	s := &Store{
		typed:  k8sfake.NewSimpleClientset(servedPod("shop", "reviews", "reviews-1")...),
		client: routeClient(virtualService("shop", "egress-vs", []interface{}{"istio-system/public"}, "api.stripe.com")),
	}
	if exps := s.listPodExposures(context.Background())["shop/reviews-1"]; len(exps) != 0 {
		t.Errorf("got %v, want none", exposureTypes(exps))
	}
}

// Neither CRD being installed is the common case and must not be an error. The
// fake client panics on an unregistered resource rather than answering, so the
// API server's actual response — NotFound — is injected instead.
func TestMissingRouteCRDsAreNotAnError(t *testing.T) {
	client := routeClient()
	for _, resource := range []string{"httproutes", "grpcroutes", "virtualservices"} {
		client.PrependReactor("list", resource,
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewNotFound(
					schema.GroupResource{Resource: action.GetResource().Resource}, "")
			})
	}
	s := &Store{
		typed:  k8sfake.NewSimpleClientset(servedPod("shop", "web", "web-1")...),
		client: client,
	}

	// A ClusterIP Service is not an exposure, and a missing CRD must not turn
	// into one — or into a failure that loses the other exposure types.
	if exps := s.listPodExposures(context.Background())["shop/web-1"]; len(exps) != 0 {
		t.Errorf("got %v, want none", exposureTypes(exps))
	}
}

// externalIPs is reachable from outside whatever the Service type says, and a
// ClusterIP Service carrying one used to report no exposure at all.
func TestExternalIPsOnAClusterIPServiceIsAnExposure(t *testing.T) {
	objs := servedPod("shop", "web", "web-1")
	svc := objs[0].(*corev1.Service)
	svc.Spec.ExternalIPs = []string{"203.0.113.10"}
	svc.Spec.Ports = []corev1.ServicePort{{Port: 80}}

	s := &Store{typed: k8sfake.NewSimpleClientset(objs...), client: routeClient()}
	exps := s.listPodExposures(context.Background())["shop/web-1"]
	if len(exps) != 1 || exps[0].Type != "externalip" {
		t.Fatalf("got %v, want one externalip exposure", exposureTypes(exps))
	}
	if exps[0].Address != "203.0.113.10:80" {
		t.Errorf("address = %q, want the external address and port", exps[0].Address)
	}
}

// externalIPs can sit alongside a NodePort, and each is a separate way in.
func TestExternalIPsAndNodePortAreBothReported(t *testing.T) {
	objs := servedPod("shop", "web", "web-1")
	svc := objs[0].(*corev1.Service)
	svc.Spec.Type = corev1.ServiceTypeNodePort
	svc.Spec.ExternalIPs = []string{"203.0.113.10"}
	svc.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 31906}}

	s := &Store{typed: k8sfake.NewSimpleClientset(objs...), client: routeClient()}
	types := exposureTypes(s.listPodExposures(context.Background())["shop/web-1"])
	if len(types) != 2 {
		t.Fatalf("got %v, want both paths", types)
	}
}

// A Service's endpoints span several slices, and the same pod appearing in two
// of them must not produce the exposure twice.
func TestPodListedInSeveralSlicesIsCountedOnce(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Port: 80, NodePort: 31906}},
		},
	}
	s := &Store{
		typed: k8sfake.NewSimpleClientset(
			svc,
			endpointSlice("shop", "web", "web-aaa", "web-1"),
			endpointSlice("shop", "web", "web-bbb", "web-1"),
		),
		client: routeClient(),
	}
	if exps := s.listPodExposures(context.Background())["shop/web-1"]; len(exps) != 1 {
		t.Errorf("got %v, want one", exposureTypes(exps))
	}
}

// A route alone cannot say whether it is reached over HTTP or HTTPS; only the
// Gateway's listener knows, so it has to be read.
func TestGatewayListenerSuppliesTheScheme(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]interface{}{"name": "public-gw", "namespace": "shop"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{map[string]interface{}{
				"name": "https", "protocol": "HTTPS", "port": int64(443),
			}},
		},
	}}
	s := &Store{
		typed: k8sfake.NewSimpleClientset(servedPod("shop", "web", "web-1")...),
		client: withGateway(t, routeClient(
			httpRoute("shop", "web-route", "public-gw", "shop.example.com", "", "web"),
		), gw),
	}

	exps := s.listPodExposures(context.Background())["shop/web-1"]
	if len(exps) != 1 {
		t.Fatalf("got %d exposures, want 1", len(exps))
	}
	if exps[0].Detail != "HTTPS · 443" {
		t.Errorf("detail = %q, want the listener's protocol and port", exps[0].Detail)
	}
}

// An Ingress says HTTPS only through a TLS block covering the host.
func TestIngressSchemeFollowsItsTLSBlock(t *testing.T) {
	plain := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "shop"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "shop.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: "/",
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: "web", Port: networkingv1.ServiceBackendPort{Number: 8080},
					}},
				}},
			}},
		}}},
	}
	secure := plain.DeepCopy()
	secure.Name = "secure"
	secure.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{"shop.example.com"}}}

	for _, c := range []struct {
		ing  *networkingv1.Ingress
		want string
	}{{plain, "HTTP · 80"}, {secure, "HTTPS · 443"}} {
		objs := append(servedPod("shop", "web", "web-1"), c.ing)
		s := &Store{typed: k8sfake.NewSimpleClientset(objs...), client: routeClient()}
		exps := s.listPodExposures(context.Background())["shop/web-1"]
		if len(exps) != 1 {
			t.Fatalf("%s: got %d exposures, want 1", c.ing.Name, len(exps))
		}
		if exps[0].Detail != c.want {
			t.Errorf("%s: detail = %q, want %q", c.ing.Name, exps[0].Detail, c.want)
		}
		// The Ingress itself has to be a hop, not just the Service behind it.
		if len(exps[0].Hops) != 2 || exps[0].Hops[0].Kind != "Ingress" {
			t.Errorf("%s: hops = %+v, want Ingress then Backend", c.ing.Name, exps[0].Hops)
		}
	}
}

// A pod can be reachable several ways at once, and the widest reach is the one
// worth reading first: an address on the internet is a different problem from a
// port that first needs access to a node.
func TestExposuresAreOrderedWidestFirst(t *testing.T) {
	exps := []Exposure{
		{Type: "hostport"},
		{Type: "nodeport"},
		{Type: "gateway"},
		{Type: "externalip"},
	}
	sortByReach(exps)

	want := []string{"gateway", "externalip", "nodeport", "hostport"}
	if got := exposureTypes(exps); len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if exps[i].Type != want[i] {
			t.Fatalf("order = %v, want %v", exposureTypes(exps), want)
		}
	}
}

// Two paths of equal reach keep the order they were found in, so re-reading does
// not shuffle the panel.
func TestEqualReachKeepsDetectionOrder(t *testing.T) {
	exps := []Exposure{{Type: "ingress", Address: "a"}, {Type: "gateway", Address: "b"}}
	sortByReach(exps)
	if exps[0].Address != "a" || exps[1].Address != "b" {
		t.Errorf("order changed: %+v", exps)
	}
}
