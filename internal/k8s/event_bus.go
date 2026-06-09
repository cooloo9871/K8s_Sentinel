package k8s

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// StartDiscoveryLoop runs a background goroutine that:
//  1. Scans all currently running pods via the Tetragon host-PID namespace.
//  2. Continuously streams new Tetragon process_exec events.
func (s *Store) StartDiscoveryLoop(ctx context.Context) {
	go func() {
		// Seed Discovery with processes already running before Sentinel started.
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

// scanRunningProcesses reads /proc on each node via the privileged Tetragon
// DaemonSet pod (hostPID:true). One exec per node covers ALL containers on
// that node — no exec into target containers needed.
func (s *Store) scanRunningProcesses(ctx context.Context) {
	if s.typed == nil || s.restConfig == nil {
		return
	}

	tetragonPods, err := s.findAllTetragonPods(ctx)
	if err != nil || len(tetragonPods) == 0 {
		return
	}

	// Build a UID→(namespace, name) map once for the whole scan.
	uidMap, err := s.buildPodUIDMap(ctx)
	if err != nil {
		fmt.Printf("[sentinel-discovery] scan: list pods error: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	for _, podName := range tetragonPods {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			s.scanNodeProcesses(ctx, name, uidMap)
		}(podName)
	}
	wg.Wait()
}

// buildPodUIDMap returns a map from pod UID → {namespace, podName} for all
// running pods in the cluster.
func (s *Store) buildPodUIDMap(ctx context.Context) (map[string][2]string, error) {
	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, err
	}
	m := make(map[string][2]string, len(pods.Items))
	for _, p := range pods.Items {
		uid := string(p.UID)
		// cgroupv2 encodes hyphens as underscores in slice names.
		m[uid] = [2]string{p.Namespace, p.Name}
		m[strings.ReplaceAll(uid, "-", "_")] = [2]string{p.Namespace, p.Name}
	}
	return m, nil
}

// podUIDRe matches the pod UID embedded in a cgroup path, e.g.
//
//	/kubepods/burstable/pod7e17d1a0-e83f-4e0b-bc8d-b7cc67deef86/…
//	/kubepods-besteffort-pod7e17d1a0_e83f_4e0b_bc8d_b7cc67deef86.slice/…
var podUIDRe = regexp.MustCompile(`pod([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})`)

// scanNodeProcesses execs once into a Tetragon pod and reads the host /proc
// to enumerate all container processes on that node.
//
// The script outputs tab-separated lines: <binary>\t<cgroup-line>
// A Tetragon pod has hostPID:true so /proc lists every process on the host.
func (s *Store) scanNodeProcesses(ctx context.Context, tetragonPodName string, uidMap map[string][2]string) {
	const script = `for pid in /proc/[0-9]*/; do
  exe=$(readlink "${pid}exe" 2>/dev/null) || continue
  [ -z "$exe" ] && continue
  echo "$exe" | grep -q " (deleted)" && continue
  cg=$(head -1 "${pid}cgroup" 2>/dev/null) || continue
  printf '%s\t%s\n' "$exe" "$cg"
done`

	req := s.typed.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(tetragonPodName).
		Namespace("kube-system").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "tetragon",
			Command:   []string{"sh", "-c", script},
			Stdin:     false,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return
	}

	scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var buf bytes.Buffer
	_ = executor.StreamWithContext(scanCtx, remotecommand.StreamOptions{Stdout: &buf})

	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range strings.Split(buf.String(), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		binary, cgroup := strings.TrimSpace(parts[0]), parts[1]
		if binary == "" {
			continue
		}

		// Extract pod UID from cgroup path and resolve to namespace/pod.
		m := podUIDRe.FindStringSubmatch(cgroup)
		if m == nil {
			continue // kernel/host process with no pod cgroup
		}
		uid := m[1]
		info, ok := uidMap[uid]
		if !ok {
			info, ok = uidMap[strings.ReplaceAll(uid, "-", "_")]
			if !ok {
				continue
			}
		}
		s.Discovery.Update(TetragonEvent{
			Type:      "exec",
			Namespace: info[0],
			Pod:       info[1],
			Binary:    binary,
			Time:      now,
		})
	}
}
