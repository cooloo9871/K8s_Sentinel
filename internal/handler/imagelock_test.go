package handler

import (
	"context"
	"net/http"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

// Sentinel writes an image lock's list. A hand edit would be gone at the next
// rollout, so it is refused where it is made.
func TestAnImageLockIsNotEditedByHand(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpoliciesnamespaced"}
	lock := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicyNamespaced",
		"metadata": map[string]any{
			"name": "image-lock-web", "namespace": "shop",
			"annotations": map[string]any{"sentinel.io/image-lock": "Deployment/web"},
		},
		"spec": map[string]any{},
	}}
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		gvr: "TracingPolicyNamespacedList",
	})
	if _, err := client.Resource(gvr).Namespace("shop").Create(context.Background(), lock, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	store := k8s.NewStore(client, nil, nil, "")

	body := `{"source":"yaml","rawYaml":"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicyNamespaced\nmetadata:\n  name: image-lock-web\n  namespace: shop\nspec: {}\n"}`
	rec, req := putPolicy("image-lock-web", "shop", body)
	updatePolicy(store)(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}
