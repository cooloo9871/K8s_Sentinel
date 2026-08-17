package k8s

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The YAML editor shows the object as the cluster returned it — server-owned
// metadata included — and ApplyRaw tries Create first. The apiserver refuses a
// resourceVersion on create before it would say AlreadyExists, so the Update
// fallback was unreachable: saving an edited policy always failed while the
// same YAML passed kubectl edit. The reactor plays the apiserver's part here,
// because the fake client does not enforce that rule itself.
func TestApplyRawUpdatesAPolicyTheClusterReturned(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		tracingPolicyGVR:           "TracingPolicyList",
		tracingPolicyNamespacedGVR: "TracingPolicyNamespacedList",
	}, tracingPolicy("watch-exec"))
	client.PrependReactor("create", "tracingpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		obj := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		if obj.GetResourceVersion() != "" {
			return true, nil, fmt.Errorf("resourceVersion should not be set on objects to be created")
		}
		return false, nil, nil
	})
	s := NewStore(client, nil, nil, "")

	raw := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: watch-exec
  resourceVersion: "12345"
  uid: 5e2f1a-8c
  generation: 3
spec:
  kprobes: []
`
	if err := s.ApplyRaw(context.Background(), raw, "admin"); err != nil {
		t.Fatalf("ApplyRaw on a cluster-returned manifest failed: %v", err)
	}
}
