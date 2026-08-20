package k8s

import (
	"sort"
	"sync"
	"time"
)

// IngestionHealth tracks whether Sentinel is actually receiving events from
// each ingestion source, as opposed to whether the source's pod is merely
// running. A Tetragon agent's pod can be Ready while Sentinel cannot reach its
// gRPC stream at all — the worst failure mode for a security product is looking
// like it is monitoring while it is blind — so this records, per source, the
// live connection state and the last time an event actually arrived.
//
// Sources are keyed by node for Tetragon (one agent per node) and a single
// entry for Hubble (one aggregated relay stream). All methods are safe for
// concurrent use and safe to call on a nil receiver, so wiring them into the
// stream paths never needs a guard.
type IngestionHealth struct {
	mu       sync.Mutex
	tetragon map[string]*sourceHealth
	hubble   *sourceHealth
	now      func() time.Time
}

type sourceHealth struct {
	connected           bool
	consecutiveFailures int
	eventCount          uint64
	lastConnectAt       time.Time
	lastEventAt         time.Time
	lastError           string
	lastErrorAt         time.Time
}

// SourceStatus is the outward, JSON-friendly snapshot of one source's health.
type SourceStatus struct {
	Kind                string `json:"kind"` // "tetragon" | "hubble"
	Name                string `json:"name"` // node name for Tetragon, "hubble" for Hubble
	Connected           bool   `json:"connected"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	EventCount          uint64 `json:"eventCount"`
	LastConnectAt       string `json:"lastConnectAt,omitempty"`
	LastEventAt         string `json:"lastEventAt,omitempty"`
	LastError           string `json:"lastError,omitempty"`
	LastErrorAt         string `json:"lastErrorAt,omitempty"`
}

func NewIngestionHealth() *IngestionHealth {
	return &IngestionHealth{
		tetragon: make(map[string]*sourceHealth),
		hubble:   &sourceHealth{},
		now:      time.Now,
	}
}

// tetragonSource returns the per-node record, creating it on first use so a
// node whose very first connection attempt fails is still recorded.
func (h *IngestionHealth) tetragonSource(node string) *sourceHealth {
	s := h.tetragon[node]
	if s == nil {
		s = &sourceHealth{}
		h.tetragon[node] = s
	}
	return s
}

// markConnected records a successful stream establishment: connected, and the
// failure streak cleared. Kept as a helper so Tetragon and Hubble share it.
func markConnected(s *sourceHealth, at time.Time) {
	s.connected = true
	s.consecutiveFailures = 0
	s.lastConnectAt = at
}

func markError(s *sourceHealth, err error, at time.Time) {
	s.connected = false
	s.consecutiveFailures++
	if err != nil {
		s.lastError = err.Error()
		s.lastErrorAt = at
	}
}

func markEvent(s *sourceHealth, at time.Time) {
	s.eventCount++
	s.lastEventAt = at
	// A stream delivering events is connected even if MarkConnected was missed
	// (e.g. Hubble, whose connect point is the first flow), and clears any stale
	// failure streak so a recovered source never shows connected-yet-failing.
	s.connected = true
	s.consecutiveFailures = 0
}

func (h *IngestionHealth) MarkTetragonConnected(node string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markConnected(h.tetragonSource(node), h.now())
}

func (h *IngestionHealth) MarkTetragonError(node string, err error) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markError(h.tetragonSource(node), err, h.now())
}

func (h *IngestionHealth) MarkTetragonEvent(node string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markEvent(h.tetragonSource(node), h.now())
}

func (h *IngestionHealth) MarkHubbleConnected() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markConnected(h.hubble, h.now())
}

func (h *IngestionHealth) MarkHubbleError(err error) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markError(h.hubble, err, h.now())
}

func (h *IngestionHealth) MarkHubbleEvent() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	markEvent(h.hubble, h.now())
}

// TetragonStatus returns the recorded health for one node, and whether any was
// recorded. Used to fold ingestion state into the per-agent view.
func (h *IngestionHealth) TetragonStatus(node string) (SourceStatus, bool) {
	if h == nil {
		return SourceStatus{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.tetragon[node]
	if s == nil {
		return SourceStatus{}, false
	}
	return s.snapshot("tetragon", node), true
}

// PruneTetragon drops recorded nodes that are no longer present, so a cluster
// that scales down does not leave dead nodes showing as permanently blind and
// the map does not grow without bound. `alive` is the set of node keys that
// currently exist.
func (h *IngestionHealth) PruneTetragon(alive map[string]bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for node := range h.tetragon {
		if !alive[node] {
			delete(h.tetragon, node)
		}
	}
}

// Snapshot returns every source's status, Tetragon nodes sorted by name then
// the Hubble entry, so the order is stable for display and tests.
func (h *IngestionHealth) Snapshot() []SourceStatus {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	nodes := make([]string, 0, len(h.tetragon))
	for node := range h.tetragon {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	out := make([]SourceStatus, 0, len(nodes)+1)
	for _, node := range nodes {
		out = append(out, h.tetragon[node].snapshot("tetragon", node))
	}
	out = append(out, h.hubble.snapshot("hubble", "hubble"))
	return out
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *sourceHealth) snapshot(kind, name string) SourceStatus {
	return SourceStatus{
		Kind:                kind,
		Name:                name,
		Connected:           s.connected,
		ConsecutiveFailures: s.consecutiveFailures,
		EventCount:          s.eventCount,
		LastConnectAt:       rfc3339(s.lastConnectAt),
		LastEventAt:         rfc3339(s.lastEventAt),
		LastError:           s.lastError,
		LastErrorAt:         rfc3339(s.lastErrorAt),
	}
}
