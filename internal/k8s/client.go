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
)

// NewDynamicClient creates a dynamic k8s client using in-cluster config.
func NewDynamicClient() (dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(cfg)
}

// NewTypedClient creates a typed k8s client using in-cluster config.
func NewTypedClient() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
