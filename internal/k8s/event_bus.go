package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// StartDiscoveryLoop seeds Discovery with already-running processes, then
// continuously streams new process_exec events from Tetragon.
func (s *Store) StartDiscoveryLoop(ctx context.Context) {
	go func() {
		s.scanRunningProcesses(ctx)

		for {
			if ctx.Err() != nil {
				return
			}
			s.runDiscoveryOnce(ctx)
			if ctx.Err() != nil {
				return
			}
			fmt.Println("[sentinel-discovery] stream ended — reconnecting in 10s")
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
}

func (s *Store) runDiscoveryOnce(ctx context.Context) {
	events := make(chan TetragonEvent, 256)
	go func() {
		defer close(events)
		if err := s.StreamTetragonEvents(ctx, events); err != nil && ctx.Err() == nil {
			fmt.Printf("[sentinel-discovery] stream error: %v\n", err)
		}
	}()
	for evt := range events {
		s.Discovery.Update(evt)
	}
}

// scanRunningProcesses execs "tetra dump process-cache" in each Tetragon pod.
// tetra connects to the local Unix socket and dumps ALL processes Tetragon
// has tracked (including those running before Sentinel started).
// Falls back to pod-spec seeding if the command is unavailable.
func (s *Store) scanRunningProcesses(ctx context.Context) {
	if s.typed == nil || s.restConfig == nil {
		return
	}
	pods, err := s.findAllTetragonPods(ctx)
	if err != nil || len(pods) == 0 {
		s.seedFromPodSpecs(ctx)
		return
	}

	total := 0
	anyOK := false
	for _, podName := range pods {
		n, err := s.dumpProcessCacheViaTetra(ctx, podName)
		if err != nil {
			fmt.Printf("[sentinel-discovery] dump %s: %v\n", podName, err)
		} else {
			total += n
			anyOK = true
		}
	}
	if !anyOK {
		s.seedFromPodSpecs(ctx)
		return
	}
	fmt.Printf("[sentinel-discovery] seeded %d processes via tetra dump\n", total)
}

// dumpProcessCacheViaTetra runs "tetra dump process-cache" inside the Tetragon
// pod container. tetra talks to the local Unix socket at
// /var/run/cilium/tetragon/tetragon.sock and outputs the full process cache
// as JSON. This command was added in Tetragon v1.3.
func (s *Store) dumpProcessCacheViaTetra(ctx context.Context, podName string) (int, error) {
	req := s.typed.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace("kube-system").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "tetragon",
			Command:   []string{"tetra", "dump", "process-cache"},
			Stdin:     false,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return 0, fmt.Errorf("exec setup: %w", err)
	}

	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var buf bytes.Buffer
	if err := executor.StreamWithContext(execCtx, remotecommand.StreamOptions{Stdout: &buf}); err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	if buf.Len() == 0 {
		return 0, fmt.Errorf("empty output (tetra dump process-cache may not be available)")
	}

	return s.parseAndSeedProcessCache(buf.Bytes())
}

// parseAndSeedProcessCache decodes JSON from "tetra dump process-cache" and
// feeds each process into the Discovery store.
//
// Expected format:
//
//	{"processes":[{"process":{"binary":"...","pod":{"namespace":"...","name":"..."}}},...]}
func (s *Store) parseAndSeedProcessCache(data []byte) (int, error) {
	var doc struct {
		Processes []struct {
			Process struct {
				Binary string `json:"binary"`
				Pod    *struct {
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
				} `json:"pod"`
			} `json:"process"`
		} `json:"processes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	count := 0
	for _, entry := range doc.Processes {
		p := entry.Process
		if p.Binary == "" || p.Pod == nil || p.Pod.Namespace == "" || p.Pod.Name == "" {
			continue
		}
		s.Discovery.Update(TetragonEvent{
			Type:      "exec",
			Namespace: p.Pod.Namespace,
			Pod:       p.Pod.Name,
			Binary:    p.Binary,
			Time:      now,
		})
		count++
	}
	return count, nil
}

// seedFromPodSpecs is the final fallback when tetra dump is unavailable.
func (s *Store) seedFromPodSpecs(ctx context.Context) {
	if s.typed == nil {
		return
	}
	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	count := 0
	for _, pod := range pods.Items {
		for _, c := range pod.Spec.Containers {
			if len(c.Command) > 0 && c.Command[0] != "" {
				s.Discovery.Update(TetragonEvent{
					Type: "exec", Namespace: pod.Namespace, Pod: pod.Name,
					Binary: c.Command[0], Time: now,
				})
				count++
			}
		}
	}
	fmt.Printf("[sentinel-discovery] seeded %d processes from pod specs (fallback)\n", count)
}
