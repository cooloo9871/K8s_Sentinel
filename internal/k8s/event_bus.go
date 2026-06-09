package k8s

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

func init() {
	// Register a raw-bytes codec so we can send/receive protobuf as []byte
	// without importing the full Tetragon protobuf module.
	encoding.RegisterCodec(rawBytesCodec{})
}

// rawBytesCodec passes []byte straight through the gRPC codec layer.
type rawBytesCodec struct{}

func (rawBytesCodec) Name() string { return "proto" }

func (rawBytesCodec) Marshal(v interface{}) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return []byte{}, nil
}

func (rawBytesCodec) Unmarshal(data []byte, v interface{}) error {
	if p, ok := v.(*[]byte); ok {
		*p = append(*p, data...)
	}
	return nil
}

// StartDiscoveryLoop runs a background goroutine that:
//  1. Seeds Discovery via Tetragon's DumpProcessCache gRPC (all tracked processes).
//  2. Continuously streams new process_exec events.
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

// scanRunningProcesses calls Tetragon's DumpProcessCache gRPC on each node to
// get ALL processes Tetragon is tracking — including those that started before
// Sentinel was deployed. Falls back to pod-spec seeding if gRPC fails.
func (s *Store) scanRunningProcesses(ctx context.Context) {
	if s.typed == nil {
		return
	}

	pods, err := s.findTetragonPodsWithIPs(ctx)
	if err != nil || len(pods) == 0 {
		s.seedFromPodSpecs(ctx)
		return
	}

	total := 0
	anyOK := false
	for _, info := range pods {
		n, err := s.dumpProcessCacheFromNode(ctx, info[0], info[1])
		if err != nil {
			fmt.Printf("[sentinel-discovery] gRPC %s (%s): %v\n", info[0], info[1], err)
		} else {
			total += n
			anyOK = true
		}
	}
	if !anyOK {
		s.seedFromPodSpecs(ctx)
		return
	}
	fmt.Printf("[sentinel-discovery] seeded %d processes via Tetragon gRPC\n", total)
}

func (s *Store) findTetragonPodsWithIPs(ctx context.Context) ([][2]string, error) {
	for _, sel := range []string{"app.kubernetes.io/name=tetragon", "app=tetragon"} {
		list, err := s.typed.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err == nil && len(list.Items) > 0 {
			var result [][2]string
			for _, p := range list.Items {
				if p.Status.PodIP != "" {
					result = append(result, [2]string{p.Name, p.Status.PodIP})
				}
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("no Tetragon pods found")
}

func (s *Store) dumpProcessCacheFromNode(ctx context.Context, podName, podIP string) (int, error) {
	addr := fmt.Sprintf("%s:54321", podIP)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	rpcCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req := []byte{} // DumpProcessCacheReqParams is an empty message
	var resp []byte
	if err := conn.Invoke(rpcCtx,
		"/tetragon.FineGuidanceSensors/DumpProcessCache",
		req, &resp,
	); err != nil {
		return 0, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	entries := decodeProcessCacheList(resp)
	count := 0
	for _, e := range entries {
		if e.namespace == "" || e.pod == "" || e.binary == "" {
			continue
		}
		s.Discovery.Update(TetragonEvent{
			Type: "exec", Namespace: e.namespace, Pod: e.pod,
			Binary: e.binary, Time: now,
		})
		count++
	}
	fmt.Printf("[sentinel-discovery] %s: %d processes from cache\n", podName, count)
	return count, nil
}

// seedFromPodSpecs is a fallback when Tetragon gRPC is unavailable.
func (s *Store) seedFromPodSpecs(ctx context.Context) {
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
