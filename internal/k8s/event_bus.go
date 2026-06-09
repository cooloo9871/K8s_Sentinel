package k8s

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StartDiscoveryLoop runs a background goroutine that:
//  1. Seeds Discovery with already-running pod processes from pod specs.
//  2. Continuously streams new Tetragon process_exec events.
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

// scanRunningProcesses seeds Discovery by reading each container's command
// from the Kubernetes Pod spec — no exec needed, works for all container
// types including distroless. Covers the entrypoint (command[0]); the
// Tetragon process_exec stream fills in additional processes over time.
func (s *Store) scanRunningProcesses(ctx context.Context) {
	if s.typed == nil {
		return
	}
	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		fmt.Printf("[sentinel-discovery] seed: list pods error: %v\n", err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	count := 0
	for _, pod := range pods.Items {
		ns := pod.Namespace
		podName := pod.Name
		for _, c := range pod.Spec.Containers {
			if len(c.Command) > 0 && c.Command[0] != "" {
				s.Discovery.Update(TetragonEvent{
					Type:      "exec",
					Namespace: ns,
					Pod:       podName,
					Binary:    c.Command[0],
					Time:      now,
				})
				count++
			}
		}
	}
	fmt.Printf("[sentinel-discovery] seeded %d processes from %d running pods\n", count, len(pods.Items))
}
