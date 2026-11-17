package k8s

import (
	"context"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type resolvedPod struct {
	pod       string
	namespace string
	container string
	cachedAt  time.Time
}

// fresh reports whether a cached answer still stands. A container that was
// found stays found for half a minute. One that was not may be a container
// that started this instant and is not in its pod's status yet, so that
// answer lasts only long enough for the events arriving together to share it.
func (c resolvedPod) fresh() bool {
	if c.pod == "" {
		return time.Since(c.cachedAt) < 2*time.Second
	}
	return time.Since(c.cachedAt) < 30*time.Second
}

// containerResolver maps container IDs to pod info with a 30-second TTL cache.
type containerResolver struct {
	mu    sync.RWMutex
	cache map[string]resolvedPod
}

func newContainerResolver() *containerResolver {
	return &containerResolver{cache: make(map[string]resolvedPod)}
}

// resolve looks up a container ID against Kubernetes pods.
// On a cache miss it lists all pods in one API call and caches every ID found.
func (r *containerResolver) resolve(ctx context.Context, s *Store, containerID string) (pod, namespace, container string) {
	if containerID == "" || s.typed == nil {
		return
	}

	r.mu.RLock()
	if c, ok := r.cache[containerID]; ok && c.fresh() {
		r.mu.RUnlock()
		return c.pod, c.namespace, c.container
	}
	r.mu.RUnlock()

	// Upgrade to write lock and re-check before making the API call.
	// This prevents multiple goroutines from issuing simultaneous Pod list
	// requests on a cache miss (thundering herd).
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cache[containerID]; ok && c.fresh() {
		return c.pod, c.namespace, c.container
	}

	pods, err := s.typed.CoreV1().Pods("").List(ctx, fromCache)
	if err != nil {
		return
	}
	// Evict expired entries to prevent unbounded cache growth.
	for id, c := range r.cache {
		if !c.fresh() {
			delete(r.cache, id)
		}
	}
	for _, p := range pods.Items {
		statuses := append(append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...),
			p.Status.ContainerStatuses...), p.Status.EphemeralContainerStatuses...)
		for _, cs := range statuses {
			id := stripCRIPrefix(cs.ContainerID)
			if id == "" {
				continue
			}
			r.cache[id] = resolvedPod{
				pod:       p.Name,
				namespace: p.Namespace,
				container: cs.Name,
				cachedAt:  time.Now(),
			}
			if id == containerID {
				pod = p.Name
				namespace = p.Namespace
				container = cs.Name
			}
		}
	}
	// Remember that this ID is not a running container, or it never gets cached
	// and the next event carrying it lists every pod again. Container IDs that
	// resolve to nothing are ordinary — a container that has already exited, or
	// runc acting on a sandbox — so under churn this was a full pod list per
	// event, each one a quorum read.
	if pod == "" {
		r.cache[containerID] = resolvedPod{cachedAt: time.Now()}
	}
	return
}

// stripCRIPrefix removes "containerd://", "docker://", etc.
func stripCRIPrefix(id string) string {
	if i := strings.LastIndex(id, "//"); i >= 0 {
		return id[i+2:]
	}
	return id
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
