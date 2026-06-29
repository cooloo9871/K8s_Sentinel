package k8s

import (
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
	eventsGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "events",
	}
	ciliumNodeGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnodes",
	}
)

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
