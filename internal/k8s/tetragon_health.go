package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TetragonAgentStatus holds health information for one Tetragon DaemonSet pod.
// The Ingest* fields carry the real ingestion state — whether Sentinel's gRPC
// stream to this agent is actually connected and delivering — which pod
// readiness alone cannot tell us.
type TetragonAgentStatus struct {
	PodName      string `json:"podName"`
	NodeName     string `json:"nodeName"`
	Phase        string `json:"phase"` // Running / Pending / Failed / Unknown
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restartCount"`
	StartedAt    string `json:"startedAt,omitempty"`
	Message      string `json:"message,omitempty"` // reason if not ready

	IngestObserved    bool   `json:"ingestObserved"` // false = no stream attempt recorded yet
	IngestConnected   bool   `json:"ingestConnected"`
	IngestFailures    int    `json:"ingestFailures"`
	IngestLastEventAt string `json:"ingestLastEventAt,omitempty"`
	IngestLastError   string `json:"ingestLastError,omitempty"`
}

// ingestKey is the ingestion-health map key for an agent: its node, falling
// back to the pod name when the node is unset — matching how findAllTetragonPods
// keys the write side, so reads and writes never disagree.
func ingestKey(a TetragonAgentStatus) string {
	if a.NodeName != "" {
		return a.NodeName
	}
	return a.PodName
}

// GetTetragonAgents returns the health status of all Tetragon DaemonSet pods.
func (s *Store) GetTetragonAgents(ctx context.Context) ([]TetragonAgentStatus, error) {
	if s.typed == nil {
		return nil, fmt.Errorf("kubernetes client not initialised")
	}

	var agents []TetragonAgentStatus

	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods(tetragonNamespace()).List(ctx, metav1.ListOptions{
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
			if st, ok := s.ingestion.TetragonStatus(ingestKey(agent)); ok {
				agent.IngestObserved = true
				agent.IngestConnected = st.Connected
				agent.IngestFailures = st.ConsecutiveFailures
				agent.IngestLastEventAt = st.LastEventAt
				agent.IngestLastError = st.LastError
			}
			agents = append(agents, agent)
		}
		// Drop ingestion health for nodes that no longer have an agent pod, so a
		// scaled-down node does not linger as a permanently-blind source.
		alive := make(map[string]bool, len(agents))
		for _, a := range agents {
			alive[ingestKey(a)] = true
		}
		s.ingestion.PruneTetragon(alive)
		return agents, nil
	}

	return agents, nil
}
