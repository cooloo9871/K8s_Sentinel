package k8s

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TetragonEvent is a normalised Tetragon runtime event for the frontend.
type TetragonEvent struct {
	Type       string `json:"type"`       // "exec", "exit", "kprobe"
	Time       string `json:"time"`
	NodeName   string `json:"nodeName"`
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Binary     string `json:"binary"`
	Arguments  string `json:"arguments"`
	ParentBin  string `json:"parentBin"`
	Action     string `json:"action"`     // "monitor" or "kill"
	PolicyName string `json:"policyName"`
	Function   string `json:"function"`
}

// StreamTetragonEvents finds a Tetragon DaemonSet pod and streams parsed events
// into the returned channel. The channel is closed when streaming ends.
func (s *Store) StreamTetragonEvents(ctx context.Context, out chan<- TetragonEvent) error {
	if s.typed == nil {
		return fmt.Errorf("typed kubernetes client not available")
	}

	// Find Tetragon pods (try common label selectors)
	podName, err := s.findTetragonPod(ctx)
	if err != nil {
		return err
	}

	tailLines := int64(100)
	req := s.typed.CoreV1().Pods("kube-system").GetLogs(podName, &corev1.PodLogOptions{
		Container: "tetragon",
		Follow:    true,
		TailLines: &tailLines,
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("open log stream for pod %s: %w", podName, err)
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		evt, ok := parseTetragonLog(scanner.Text())
		if !ok {
			continue
		}

		select {
		case out <- evt:
		case <-ctx.Done():
			return nil
		}
	}

	return scanner.Err()
}

func (s *Store) findTetragonPod(ctx context.Context) (string, error) {
	selectors := []string{
		"app.kubernetes.io/name=tetragon",
		"app=tetragon",
	}
	for _, sel := range selectors {
		list, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: sel,
		})
		if err == nil && len(list.Items) > 0 {
			return list.Items[0].Name, nil
		}
	}
	return "", fmt.Errorf("no Tetragon pods found in kube-system (is Tetragon installed?)")
}

func parseTetragonLog(line string) (TetragonEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return TetragonEvent{}, false
	}

	evt := TetragonEvent{
		Time:     strField(raw, "time"),
		NodeName: strField(raw, "node_name"),
	}

	switch {
	case raw["process_exec"] != nil:
		evt.Type = "exec"
		fillProcess(&evt, mapField(raw, "process_exec"), "process")
		if parent := mapField(mapField(raw, "process_exec"), "parent"); parent != nil {
			evt.ParentBin = strField(parent, "binary")
		}

	case raw["process_exit"] != nil:
		evt.Type = "exit"
		fillProcess(&evt, mapField(raw, "process_exit"), "process")

	case raw["process_kprobe"] != nil:
		evt.Type = "kprobe"
		kp := mapField(raw, "process_kprobe")
		fillProcess(&evt, kp, "process")
		evt.Function = strField(kp, "function_name")
		evt.PolicyName = strField(kp, "policy_name")
		action := strField(kp, "action")
		if strings.Contains(strings.ToUpper(action), "SIGKILL") {
			evt.Action = "kill"
		} else {
			evt.Action = "monitor"
		}

	default:
		return TetragonEvent{}, false
	}

	return evt, true
}

func fillProcess(evt *TetragonEvent, parent map[string]any, key string) {
	proc := mapField(parent, key)
	if proc == nil {
		return
	}
	evt.Binary = strField(proc, "binary")
	evt.Arguments = strField(proc, "arguments")

	pod := mapField(proc, "pod")
	if pod == nil {
		return
	}
	evt.Namespace = strField(pod, "namespace")
	evt.Pod = strField(pod, "name")
	if c := mapField(pod, "container"); c != nil {
		evt.Container = strField(c, "name")
	}
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func mapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]any)
	return v
}
