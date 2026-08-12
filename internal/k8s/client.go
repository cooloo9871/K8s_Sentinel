package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	tracingPolicyGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "tracingpolicies",
	}
	tracingPolicyNamespacedGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "tracingpoliciesnamespaced",
	}
	namespaceGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}
	ciliumNodeGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnodes",
	}
)

// fromCache asks the API server to answer from its watch cache instead of
// reading through to etcd.
//
// A List with no ResourceVersion means "give me the newest data", which the API
// server can only satisfy with a quorum read from etcd. Every list here was
// doing that, several of them on a timer, and a full pod list is the most
// expensive shape of it — which is how a monitoring console ends up showing on
// the API server's CPU graph.
//
// The cost is that the answer may lag by moments. Every list using this sits
// behind a TTL cache measured in tens of seconds, or enriches a view that is
// already a snapshot, so it was never reading the newest data anyway.
//
// Deliberately NOT used where a read follows a write the user just made — the
// policy and quarantine lists reload right after applying a change, and the
// watch cache can lag far enough to look like the change was lost.
var fromCache = metav1.ListOptions{ResourceVersion: "0"}

// NewClients creates dynamic, typed, and raw REST config from in-cluster config.
// All three share the same underlying config, so only one in-cluster lookup is made.
func NewClients() (dynamic.Interface, *kubernetes.Clientset, *rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return dyn, typed, cfg, nil
}
