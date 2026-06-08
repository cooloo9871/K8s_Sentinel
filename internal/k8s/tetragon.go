package k8s

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// TetragonEvent is a normalised Tetragon runtime event for the frontend.
type TetragonEvent struct {
	Type       string `json:"type"`
	Time       string `json:"time"`
	NodeName   string `json:"nodeName"`
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Binary     string `json:"binary"`
	Arguments  string `json:"arguments"`
	ParentBin  string `json:"parentBin"`
	Action     string `json:"action"` // "monitor" or "kill"
	PolicyName string `json:"policyName"`
	Function   string `json:"function"`
	FilePath   string `json:"filePath"` // extracted from file_arg (security_file_permission)
	NetDest    string `json:"netDest"`  // extracted from sock_arg daddr:dport (tcp_connect)
}

// StreamTetragonEvents streams events from ALL Tetragon pods concurrently.
// In a multi-node cluster each pod only sees its own node's events, so we
// must aggregate all pods to get complete cluster coverage.
func (s *Store) StreamTetragonEvents(ctx context.Context, out chan<- TetragonEvent) error {
	if s.typed == nil || s.restConfig == nil {
		return fmt.Errorf("kubernetes clients not initialised")
	}

	pods, err := s.findAllTetragonPods(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, podName := range pods {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_ = s.streamFromPod(ctx, name, out) // errors logged; one pod failing won't stop others
		}(podName)
	}
	wg.Wait()
	return nil
}

func (s *Store) streamFromPod(ctx context.Context, podName string, out chan<- TetragonEvent) error {
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
		return fmt.Errorf("exec %s: %w", podName, err)
	}

	pr, pw := io.Pipe()
	defer pr.Close()

	execDone := make(chan error, 1)
	go func() {
		defer pw.Close()
		execDone <- executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: pw})
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

func (s *Store) findAllTetragonPods(ctx context.Context) ([]string, error) {
	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: sel,
		})
		if err == nil && len(list.Items) > 0 {
			names := make([]string, len(list.Items))
			for i, p := range list.Items {
				names[i] = p.Name
			}
			return names, nil
		}
	}
	return nil, fmt.Errorf("no Tetragon pods found in kube-system (is Tetragon installed?)")
}

// parseTetragonLog parses a single JSON line from tetra getevents -o json.
// Only process_kprobe events are forwarded (policy-triggered).
func parseTetragonLog(line string) (TetragonEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return TetragonEvent{}, false
	}

	// Only process_kprobe events are triggered by TracingPolicies
	kp := anyMap(raw, "process_kprobe", "processKprobe")
	if kp == nil {
		return TetragonEvent{}, false
	}

	evt := TetragonEvent{
		Type:     "kprobe",
		Time:     anyStr(raw, "time"),
		NodeName: anyStr(raw, "node_name", "nodeName"),
	}

	fillProcess(&evt, anyMap(kp, "process"))
	evt.Function = anyStr(kp, "function_name", "functionName")
	evt.PolicyName = anyStr(kp, "policy_name", "policyName")

	action := anyStr(kp, "action")
	if strings.Contains(strings.ToUpper(action), "SIGKILL") {
		evt.Action = "kill"
	} else {
		evt.Action = "monitor"
	}

	// Extract additional context from kprobe args for Behavior Discovery.
	if args, ok := kp["args"].([]any); ok {
		for _, a := range args {
			argMap, ok := a.(map[string]any)
			if !ok {
				continue
			}
			// execve: args[0] contains the executed binary path
			if strings.Contains(evt.Function, "execve") {
				if bin := anyStr(argMap, "string_arg", "stringArg"); bin != "" {
					evt.ParentBin = evt.Binary
					evt.Binary = bin
				}
			}
			// security_file_permission: args[0] is file_arg with path
			if fileArg := anyMap(argMap, "file_arg", "fileArg"); fileArg != nil {
				evt.FilePath = anyStr(fileArg, "path")
			}
			// tcp_connect: args[0] is sock_arg with daddr/dport
			if sockArg := anyMap(argMap, "sock_arg", "sockArg"); sockArg != nil {
				daddr := anyStr(sockArg, "daddr", "dest_addr", "destAddr")
				if daddr != "" {
					dport := anyStr(sockArg, "dport", "dest_port", "destPort")
					if dport == "" {
						if dp, ok := sockArg["dport"].(float64); ok && dp > 0 {
							dport = fmt.Sprintf("%d", int(dp))
						}
					}
					if dport != "" && dport != "0" {
						evt.NetDest = fmt.Sprintf("%s:%s", daddr, dport)
					} else {
						evt.NetDest = daddr
					}
				}
			}
		}
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
