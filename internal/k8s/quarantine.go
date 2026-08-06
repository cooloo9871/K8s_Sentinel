package k8s

import (
	"context"
	"fmt"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Quarantine cuts a pod off from the network without killing it, so the process,
// its memory and its open files are still there to look at.
//
// It works by labelling the pod and letting one standing cluster-wide policy
// select that label — not by writing a policy per pod. A CiliumNetworkPolicy
// selects endpoints by label anyway, so a per-pod policy would need a unique
// label as well; this way there is one object to read, one to undo, and the
// cluster rather than Sentinel's storage is the record of who is contained.
// That also means a Sentinel restart cannot lose track of it.
const (
	// QuarantineLabel marks a pod as contained. Its presence is the whole
	// mechanism: remove it and the pod is released.
	QuarantineLabel = "sentinel.io/quarantine"
	// Who asked for it and when, kept on the pod so the record travels with the
	// object rather than living somewhere that a restart would clear.
	quarantineByAnnotation = "sentinel.io/quarantined-by"
	quarantineAtAnnotation = "sentinel.io/quarantined-at"

	quarantinePolicyName = "sentinel-quarantine"
)

// QuarantinedPod is a contained pod as reported to the UI.
type QuarantinedPod struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node,omitempty"`
	By        string `json:"by,omitempty"`
	At        string `json:"at,omitempty"`
}

// quarantinePolicy is the one policy that does the containing.
//
// Ingress is an allow-list, which is what switches the endpoint to default-deny,
// and the only thing allowed in is the node. That is deliberate: the kubelet's
// probes come from there, and blocking them would fail the pod's readiness and
// then its liveness, so the container would be restarted and the Deployment
// would hand back a fresh, unquarantined pod — losing both the containment and the
// evidence. Egress is denied outright, because a deny rule beats any allow and
// there is nothing a contained pod should be reaching.
func quarantinePolicy() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumClusterwideNetworkPolicy",
		"metadata": map[string]any{
			"name": quarantinePolicyName,
			"annotations": map[string]any{
				annotationCreatedBy: "sentinel-quarantine",
			},
		},
		"spec": map[string]any{
			"description": "Managed by K8s Sentinel. Selects pods labelled " +
				QuarantineLabel + "=true and cuts them off from the network, " +
				"except for the kubelet probes that keep them alive.",
			"endpointSelector": map[string]any{
				"matchLabels": map[string]any{QuarantineLabel: "true"},
			},
			"ingress": []any{
				map[string]any{"fromEntities": []any{"host", "health"}},
			},
			"egressDeny": []any{
				map[string]any{"toEntities": []any{"all"}},
			},
		},
	}}
}

// ensureQuarantinePolicy creates the standing policy if it is not there yet, so
// the first quarantine does not silently do nothing.
func (s *Store) ensureQuarantinePolicy(ctx context.Context) error {
	_, err := s.client.Resource(ccnpGVR).Get(ctx, quarantinePolicyName, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check quarantine policy: %w", err)
	}
	if _, err := s.client.Resource(ccnpGVR).Create(ctx, quarantinePolicy(), metav1.CreateOptions{}); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return nil // another request got there first
		}
		return fmt.Errorf("create quarantine policy: %w", err)
	}
	return nil
}

// Quarantine contains a pod. The policy is ensured first: labelling a pod when
// nothing selects the label would report success and contain nothing.
func (s *Store) Quarantine(ctx context.Context, namespace, pod, by string) error {
	if namespace == "" || pod == "" {
		return fmt.Errorf("namespace and pod are required")
	}
	if err := s.ensureQuarantinePolicy(ctx); err != nil {
		return err
	}
	patch := fmt.Sprintf(
		`{"metadata":{"labels":{%q:"true"},"annotations":{%q:%q,%q:%q}}}`,
		QuarantineLabel,
		quarantineByAnnotation, by,
		quarantineAtAnnotation, time.Now().UTC().Format(time.RFC3339),
	)
	if err := s.patchPod(ctx, namespace, pod, patch); err != nil {
		return err
	}
	s.invalidateAttribution()
	return nil
}

// Release lets a pod back onto the network by removing the label. The
// annotations go with it, so a pod quarantined again later does not carry the
// previous decision's timestamp.
func (s *Store) Release(ctx context.Context, namespace, pod string) error {
	patch := fmt.Sprintf(
		`{"metadata":{"labels":{%q:null},"annotations":{%q:null,%q:null}}}`,
		QuarantineLabel, quarantineByAnnotation, quarantineAtAnnotation,
	)
	if err := s.patchPod(ctx, namespace, pod, patch); err != nil {
		return err
	}
	s.invalidateAttribution()
	return nil
}

func (s *Store) patchPod(ctx context.Context, namespace, pod, patch string) error {
	if s.typed == nil {
		return fmt.Errorf("kubernetes client not initialised")
	}
	_, err := s.typed.CoreV1().Pods(namespace).Patch(
		ctx, pod, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch pod %s/%s: %w", namespace, pod, err)
	}
	return nil
}

// ListQuarantined returns every contained pod, read from the cluster rather than
// from anything Sentinel keeps — the label is the state.
func (s *Store) ListQuarantined(ctx context.Context) ([]QuarantinedPod, error) {
	if s.typed == nil {
		return nil, fmt.Errorf("kubernetes client not initialised")
	}
	list, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: QuarantineLabel + "=true",
	})
	if err != nil {
		return nil, err
	}
	out := make([]QuarantinedPod, 0, len(list.Items))
	for _, p := range list.Items {
		out = append(out, QuarantinedPod{
			Namespace: p.Namespace,
			Pod:       p.Name,
			Node:      p.Spec.NodeName,
			By:        p.Annotations[quarantineByAnnotation],
			At:        p.Annotations[quarantineAtAnnotation],
		})
	}
	return out, nil
}

// IsQuarantined reports whether a pod is contained, from the attribution cache
// the topology already builds — the pod labels are in it, so this costs no
// extra call to the API server.
func (s *Store) IsQuarantined(ctx context.Context, namespace, pod string) bool {
	labels, ok := s.cachedAttribution(ctx).podLabels[namespace+"/"+pod]
	return ok && labels[QuarantineLabel] == "true"
}

// invalidateAttribution drops the cached pod labels so a quarantine shows on the
// topology at once rather than after the cache's own 30 seconds.
func (s *Store) invalidateAttribution() {
	s.attrMu.Lock()
	s.attrExpiry = time.Time{}
	s.attrMu.Unlock()
}
