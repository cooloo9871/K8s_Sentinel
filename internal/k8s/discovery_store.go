package k8s

import (
	"sort"
	"sync"
)

// PodProfile accumulates process binaries observed for a single pod.
// Data lives in memory for the lifetime of the Sentinel process and is
// intentionally lost on pod restart — no file persistence.
type PodProfile struct {
	Namespace    string   `json:"namespace"`
	Pod          string   `json:"pod"`
	WorkloadKind string   `json:"workloadKind,omitempty"` // "Deployment", "DaemonSet", "StatefulSet", etc.
	WorkloadName string   `json:"workloadName,omitempty"` // controller name
	Binaries     []string `json:"binaries"`
	FirstSeen    string   `json:"firstSeen"`
	LastSeen     string   `json:"lastSeen"`
}

// DiscoveryProfileStore is a pure in-memory store.
// Thread-safe; never writes to disk.
type DiscoveryProfileStore struct {
	mu       sync.RWMutex
	profiles map[string]*PodProfile
}

func NewDiscoveryProfileStore() *DiscoveryProfileStore {
	return &DiscoveryProfileStore{profiles: make(map[string]*PodProfile)}
}

// Update records a process_exec event. Non-exec and incomplete events are ignored.
func (s *DiscoveryProfileStore) Update(evt TetragonEvent) {
	if evt.Type != "exec" || evt.Namespace == "" || evt.Pod == "" || evt.Binary == "" {
		return
	}
	key := evt.Namespace + "/" + evt.Pod
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[key]
	if !ok {
		p = &PodProfile{
			Namespace: evt.Namespace,
			Pod:       evt.Pod,
			Binaries:  []string{},
			FirstSeen: evt.Time,
			LastSeen:  evt.Time,
		}
		s.profiles[key] = p
	}
	if evt.Time > p.LastSeen {
		p.LastSeen = evt.Time
	}
	if !sliceContains(p.Binaries, evt.Binary) {
		p.Binaries = append(p.Binaries, evt.Binary)
	}
}

func (s *DiscoveryProfileStore) All() []*PodProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PodProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		cp := *p
		if cp.Binaries == nil {
			cp.Binaries = []string{}
		}
		result = append(result, &cp)
	}
	sort.Slice(result, func(i, j int) bool {
		ki := result[i].Namespace + "/" + result[i].Pod
		kj := result[j].Namespace + "/" + result[j].Pod
		return ki < kj
	})
	return result
}

// SetWorkload updates the workload owner for an existing profile.
func (s *DiscoveryProfileStore) SetWorkload(namespace, pod, kind, name string) {
	key := namespace + "/" + pod
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.profiles[key]; ok {
		p.WorkloadKind = kind
		p.WorkloadName = name
	}
}

func (s *DiscoveryProfileStore) Clear() {
	s.mu.Lock()
	s.profiles = make(map[string]*PodProfile)
	s.mu.Unlock()
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
