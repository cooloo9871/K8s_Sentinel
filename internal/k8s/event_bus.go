package k8s

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// StartDiscoveryLoop runs a background goroutine that:
//  1. Scans all currently running pods to seed Discovery with existing processes.
//  2. Continuously streams new Tetragon process_exec events.
func (s *Store) StartDiscoveryLoop(ctx context.Context) {
	go func() {
		// Seed with already-running processes before streaming new events.
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

// scanRunningProcesses iterates every ready container in the cluster and
// reads /proc/*/exe to discover processes that started before Sentinel did.
// Containers without a shell (distroless) are silently skipped.
func (s *Store) scanRunningProcesses(ctx context.Context) {
	if s.typed == nil || s.restConfig == nil {
		return
	}
	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		fmt.Printf("[sentinel-discovery] scan: list pods error: %v\n", err)
		return
	}

	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, pod := range pods.Items {
		ns := pod.Namespace
		podName := pod.Name
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				continue
			}
			containerName := cs.Name
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				s.scanContainerProcesses(ctx, ns, podName, containerName)
			}()
		}
	}
	wg.Wait()
}

// scanContainerProcesses execs into a single container and collects the set of
// unique binary paths visible under /proc/*/exe.
func (s *Store) scanContainerProcesses(ctx context.Context, namespace, pod, container string) {
	req := s.typed.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   []string{"sh", "-c", "for f in /proc/*/exe; do readlink \"$f\" 2>/dev/null; done"},
			Stdin:     false,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return // container may not support exec
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var buf bytes.Buffer
	_ = executor.StreamWithContext(scanCtx, remotecommand.StreamOptions{Stdout: &buf})

	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range strings.Split(buf.String(), "\n") {
		binary := strings.TrimSpace(line)
		if binary == "" {
			continue
		}
		s.Discovery.Update(TetragonEvent{
			Type:      "exec",
			Namespace: namespace,
			Pod:       pod,
			Binary:    binary,
			Time:      now,
		})
	}
}
