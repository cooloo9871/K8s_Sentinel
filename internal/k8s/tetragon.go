package k8s

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// TetragonEvent is a normalised Tetragon runtime event for the frontend.
type TetragonEvent struct {
	Type       string `json:"type"`       // "kprobe"
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

// StreamTetragonEvents execs into a Tetragon pod and runs "tetra getevents -o json",
// parsing each JSON line into a TetragonEvent and sending it to out.
func (s *Store) StreamTetragonEvents(ctx context.Context, out chan<- TetragonEvent) error {
	if s.typed == nil || s.restConfig == nil {
		return fmt.Errorf("kubernetes clients not initialised")
	}

	podName, err := s.findTetragonPod(ctx)
	if err != nil {
		return err
	}

	req := s.typed.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace("kube-system").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "tetragon",
			Command:   []string{"tetra", "getevents", "-o", "json"},
			Stdin:     false,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("create exec for pod %s: %w", podName, err)
	}

	pr, pw := io.Pipe()
	defer pr.Close()

	execDone := make(chan error, 1)
	go func() {
		defer pw.Close()
		execDone <- executor.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: pw,
		})
	}()

	scanner := bufio.NewScanner(pr)
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

	if err := scanner.Err(); err != nil {
		return err
	}
	return <-execDone
}

func (s *Store) findTetragonPod(ctx context.Context) (string, error) {
	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: sel,
		})
		if err == nil && len(list.Items) > 0 {
			return list.Items[0].Name, nil
		}
	}
	return "", fmt.Errorf("no Tetragon pods found in kube-system (is Tetragon installed?)")
}

// parseTetragonLog handles both camelCase (protobuf JSON) and snake_case field names.
// tetra getevents -o json uses protobuf JSON encoding which outputs camelCase.
func parseTetragonLog(line string) (TetragonEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return TetragonEvent{}, false
	}

	evt := TetragonEvent{
		Time:     anyStr(raw, "time"),
		NodeName: anyStr(raw, "nodeName", "node_name"),
	}

	// Try both camelCase (protobuf JSON) and snake_case field names
	kp := anyMap(raw, "processKprobe", "process_kprobe")
	if kp == nil {
		return TetragonEvent{}, false // only process_kprobe events are policy-triggered
	}

	evt.Type = "kprobe"
	fillProcess(&evt, anyMap(kp, "process"))
	evt.Function = anyStr(kp, "functionName", "function_name")
	evt.PolicyName = anyStr(kp, "policyName", "policy_name")

	action := anyStr(kp, "action")
	if strings.Contains(strings.ToUpper(action), "SIGKILL") {
		evt.Action = "kill"
	} else {
		evt.Action = "monitor"
	}

	return evt, true
}

func fillProcess(evt *TetragonEvent, proc map[string]any) {
	if proc == nil {
		return
	}
	evt.Binary = anyStr(proc, "binary")
	evt.Arguments = anyStr(proc, "arguments")

	pod := anyMap(proc, "pod")
	if pod == nil {
		return
	}
	evt.Namespace = anyStr(pod, "namespace")
	evt.Pod = anyStr(pod, "name")
	if c := anyMap(pod, "container"); c != nil {
		evt.Container = anyStr(c, "name")
	}
}

// anyStr returns the first non-empty string value found among the given keys.
func anyStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// anyMap returns the first map value found among the given keys.
func anyMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if sub, ok := v.(map[string]any); ok {
				return sub
			}
		}
	}
	return nil
}
