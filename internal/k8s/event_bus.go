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
	s.populateWorkloadInfo(ctx)
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
			Command:   []string{"tetra", "dump", "processcache"},
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
// parseAndSeedProcessCache decodes NDJSON from "tetra dump processcache".
// Each line is one ProcessInternal object; lines without a pod field are
// host/kernel processes and are skipped.
func (s *Store) parseAndSeedProcessCache(data []byte) (int, error) {
	type line struct {
		Process struct {
			Binary string `json:"binary"`
			Pod    *struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"pod"`
		} `json:"process"`
	}

	now := time.Now().UTC().Format(time.RFC3339)
	count := 0
	for _, raw := range bytes.Split(data, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var entry line
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
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

// populateWorkloadInfo resolves pod owner references (ReplicaSet → Deployment,
// DaemonSet, StatefulSet, etc.) and stores them in each PodProfile.
// Uses only 2 batch K8s API calls regardless of pod count.
func (s *Store) populateWorkloadInfo(ctx context.Context) {
	if s.typed == nil {
		return
	}
	// 1. List all ReplicaSets to build RS → Deployment mapping.
	rsList, err := s.typed.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[sentinel-discovery] workload info: list replicasets: %v (check RBAC for apps/replicasets)\n", err)
		return
	}
	// rs "namespace/name" → {deploymentName}
	rsOwner := make(map[string]string, len(rsList.Items))
	for _, rs := range rsList.Items {
		for _, ref := range rs.OwnerReferences {
			if ref.Kind == "Deployment" {
				rsOwner[rs.Namespace+"/"+rs.Name] = ref.Name
			}
		}
	}

	// 2. List all running pods and resolve each pod's owner.
	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return
	}
	for _, pod := range pods.Items {
		if len(pod.OwnerReferences) == 0 {
			continue
		}
		ref := pod.OwnerReferences[0]
		// Skip Node-owned static pods (kube-apiserver, etcd, etc.) —
		// they appear as [Node] in Discovery which is confusing.
		if ref.Kind == "Node" {
			continue
		}
		kind, name := ref.Kind, ref.Name
		if kind == "ReplicaSet" {
			if depName, ok := rsOwner[pod.Namespace+"/"+ref.Name]; ok {
				kind, name = "Deployment", depName
			}
		}
		s.Discovery.SetWorkload(pod.Namespace, pod.Name, kind, name)
	}
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
