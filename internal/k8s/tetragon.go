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
		exec := mapField(raw, "process_exec")
		fillProcess(&evt, mapField(exec, "process"))
		if p := mapField(exec, "parent"); p != nil {
			evt.ParentBin = strField(p, "binary")
		}

	case raw["process_exit"] != nil:
		evt.Type = "exit"
		fillProcess(&evt, mapField(mapField(raw, "process_exit"), "process"))

	case raw["process_kprobe"] != nil:
		evt.Type = "kprobe"
		kp := mapField(raw, "process_kprobe")
		fillProcess(&evt, mapField(kp, "process"))
		evt.Function = strField(kp, "function_name")
		evt.PolicyName = strField(kp, "policy_name")
		if strings.Contains(strings.ToUpper(strField(kp, "action")), "SIGKILL") {
			evt.Action = "kill"
		} else {
			evt.Action = "monitor"
		}

	default:
		return TetragonEvent{}, false
	}

	return evt, true
}

func fillProcess(evt *TetragonEvent, proc map[string]any) {
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
