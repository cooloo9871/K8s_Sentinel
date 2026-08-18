package k8s

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// SelectedPod names one pod a selector matched.
type SelectedPod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// previewCap bounds how many names a preview carries. The point is "is this
// the set I meant", which the first names and the total answer; the full list
// of a wide selector is noise.
const previewCap = 15

// SelectPods evaluates a label selector against the live cluster: which pods
// would a policy with this selector govern, right now. Namespace "" means all
// namespaces. This exists because the most damaging policy mistake is a
// selector that matches something other than what the author meant — nothing,
// or everything — and the cheapest place to catch that is before Apply.
func (s *Store) SelectPods(ctx context.Context, namespace string, matchLabels map[string]string) (int, []SelectedPod, error) {
	if s.typed == nil {
		return 0, nil, fmt.Errorf("kubernetes client not initialised")
	}
	list, err := s.typed.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector:   labels.Set(matchLabels).String(),
		ResourceVersion: fromCache.ResourceVersion,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("list pods: %w", err)
	}
	pods := make([]SelectedPod, 0, len(list.Items))
	for _, p := range list.Items {
		pods = append(pods, SelectedPod{Namespace: p.Namespace, Name: p.Name})
	}
	// Deterministic order, so the preview does not reshuffle between polls.
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})
	total := len(pods)
	if len(pods) > previewCap {
		pods = pods[:previewCap]
	}
	return total, pods, nil
}
