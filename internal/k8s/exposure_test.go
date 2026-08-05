package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
			grpcRouteGVR:               "GRPCRouteList",
			istioVirtualServiceGVRs[0]: "VirtualServiceList",
			istioVirtualServiceGVRs[1]: "VirtualServiceList",
			cnpGVR:                     "CiliumNetworkPolicyList",
			ccnpGVR:                    "CiliumClusterwideNetworkPolicyList",
		},
		objs...,
	)
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

// A Service with an Endpoints object naming the pod, which is the chain every
// exposure type resolves through.
func servedPod(ns, svc, pod string) []runtime.Object {
	return []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: svc, Namespace: ns},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
		},
		&corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{Name: svc, Namespace: ns},
			Subsets: []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{
					IP:        "10.0.0.1",
					TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: pod, Namespace: ns},
				}},
			}},
		},
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
	if want := "public-gw → web"; exps[0].Via != want {
		t.Errorf("via = %q, want %q", exps[0].Via, want)
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
