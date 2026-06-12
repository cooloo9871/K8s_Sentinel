package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TetragonAgentStatus holds health information for one Tetragon DaemonSet pod.
type TetragonAgentStatus struct {
	PodName      string `json:"podName"`
	NodeName     string `json:"nodeName"`
	Phase        string `json:"phase"`    // Running / Pending / Failed / Unknown
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restartCount"`
	StartedAt    string `json:"startedAt,omitempty"`
	Message      string `json:"message,omitempty"` // reason if not ready
}

// GetTetragonAgents returns the health status of all Tetragon DaemonSet pods.
func (s *Store) GetTetragonAgents(ctx context.Context) ([]TetragonAgentStatus, error) {
	if s.typed == nil {
		return nil, fmt.Errorf("kubernetes client not initialised")
	}

	var agents []TetragonAgentStatus

	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: sel,
		})
		if err != nil || len(list.Items) == 0 {
			continue
		}
		for _, pod := range list.Items {
			agent := TetragonAgentStatus{
				PodName:  pod.Name,
				NodeName: pod.Spec.NodeName,
				Phase:    string(pod.Status.Phase),
			}

			// Find the "tetragon" container status.
			for _, cs := range pod.Status.ContainerStatuses {
				if cs.Name != "tetragon" {
					continue
				}
				agent.Ready = cs.Ready
				agent.RestartCount = cs.RestartCount
				if cs.State.Running != nil {
					agent.StartedAt = cs.State.Running.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
				}
				if !cs.Ready {
					if cs.State.Waiting != nil {
						agent.Message = cs.State.Waiting.Reason
					} else if cs.State.Terminated != nil {
						agent.Message = cs.State.Terminated.Reason
					}
				}
			}
			agents = append(agents, agent)
		}
		return agents, nil
	}

	return agents, nil
}
