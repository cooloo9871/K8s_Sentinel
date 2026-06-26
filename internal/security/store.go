package security

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

const dedupWindowSecs = 30 // dedup window is fixed by design

// Event is a persisted, deduplicated Tetragon kprobe event.
type Event struct {
	ID         string  `json:"id"`
	Time       string  `json:"time"`
	Count      int     `json:"count"`
	Severity   string  `json:"severity"` // "warning" | "critical"
	Namespace  string  `json:"namespace"`
	Pod        string  `json:"pod"`
	Container  string  `json:"container,omitempty"`
	NodeName   string  `json:"nodeName,omitempty"`
	Binary     string  `json:"binary,omitempty"`
	Arguments  string  `json:"arguments,omitempty"`
	ParentBin  string  `json:"parentBin,omitempty"`
	Function   string  `json:"function,omitempty"`
	PolicyName string  `json:"policyName,omitempty"`
	Action     string  `json:"action,omitempty"`
	ProcessUID *uint32 `json:"processUid,omitempty"`
	FilePath   string  `json:"filePath,omitempty"`
	FileOp     string  `json:"fileOp,omitempty"`
	NetDest    string  `json:"netDest,omitempty"`
	NetSrc     string  `json:"netSrc,omitempty"`
}

func severityOf(evt k8s.TetragonEvent) string {
	if evt.Action == "kill" {
		return "critical"
	}
	return "warning"
}

func sameEvent(a Event, b k8s.TetragonEvent) bool {
	return a.Namespace == b.Namespace &&
		a.Binary == b.Binary &&
		a.Pod == b.Pod &&
		a.Function == b.Function &&
		a.PolicyName == b.PolicyName &&
		a.Action == b.Action &&
		a.FilePath == b.FilePath &&
		a.FileOp == b.FileOp &&
		a.NetDest == b.NetDest &&
		a.NetSrc == b.NetSrc
}

type eventFile struct {
	Events    []Event        `json:"events"`
	Retention *RetentionConfig `json:"retention,omitempty"`
}

// RetentionConfig holds configurable retention limits for security events.
type RetentionConfig struct {
	MaxWarnings  int `json:"maxWarnings"`
	MaxCriticals int `json:"maxCriticals"`
	TTLDays      int `json:"ttlDays"`
}

func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{MaxWarnings: 500, MaxCriticals: 300, TTLDays: 7}
}

// topoKey uniquely identifies a directed connection for topology display.
type topoKey struct {
	pod, ns, nodeName, netDest string
	blocked                    bool
}

// topoEntry holds the minimal fields needed by the topology handler.
type topoEntry struct {
	Pod       string
	Namespace string
	NodeName  string
	NetSrc    string
	NetDest   string
	Action    string
	Function  string // "tcp_connect" = outbound, "inet_csk_accept" = inbound
	LastSeen  time.Time
}

// Store holds Tetragon kprobe events with file persistence and SSE fanout.
type Store struct {
	mu        sync.RWMutex
	evts      []Event // newest-first
	subs      map[chan Event]struct{}
	path      string
	flushGen  uint64     // incremented each flush; goroutine skips write if stale
	flushMu   sync.Mutex // serialises the stale-check + rename to eliminate TOCTOU
	cfg       RetentionConfig
	// topoBuf tracks unique connection pairs by time, independent of event-count retention.
	// Evicted by TTLDays (same as events), not by MaxWarnings/MaxCriticals.
	topoBuf     map[topoKey]topoEntry
	topoCleanup uint64 // counter to trigger lazy cleanup every N adds
}

func NewStore(path string) *Store {
	cfg := DefaultRetentionConfig()
	s := &Store{
		evts:    make([]Event, 0, cfg.MaxWarnings+cfg.MaxCriticals),
		subs:    make(map[chan Event]struct{}),
		path:    path,
		cfg:     cfg,
		topoBuf: make(map[topoKey]topoEntry),
	}
	s.load()
	return s
}

// updateTopoBuf records a connection into the topology buffer.
// Must be called while holding s.mu (write lock).
func (s *Store) updateTopoBuf(e Event, lastSeen time.Time) {
	if e.NetDest == "" {
		return
	}
	netDestKey := e.NetDest
	// For inbound accept events the "dest" is the remote client's IP:ephemeralPort.
	// Strip the ephemeral port so all connections from the same client IP are
	// de-duplicated to a single topoBuf entry instead of exploding per connection.
	if e.Function == "inet_csk_accept" {
		if idx := strings.LastIndex(netDestKey, ":"); idx > 0 {
			netDestKey = strings.TrimPrefix(netDestKey[:idx], "::ffff:")
		}
	}
	k := topoKey{pod: e.Pod, ns: e.Namespace, nodeName: e.NodeName, netDest: netDestKey, blocked: e.Action == "kill"}
	s.topoBuf[k] = topoEntry{Pod: e.Pod, Namespace: e.Namespace, NodeName: e.NodeName, NetSrc: e.NetSrc, NetDest: e.NetDest, Action: e.Action, Function: e.Function, LastSeen: lastSeen}
}

// SetRetention updates the retention config and reapplies caps immediately.
func (s *Store) SetRetention(cfg RetentionConfig) {
	s.mu.Lock()
	s.cfg = cfg
	s.evts = s.capBySeverity(s.evts)
	s.flush()
	s.mu.Unlock()
}

// GetRetention returns the current retention config.
func (s *Store) GetRetention() RetentionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f eventFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	if f.Retention != nil {
		s.cfg = *f.Retention
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.TTLDays)
	for _, e := range f.Events {
		t, err := parseTime(e.Time)
		if err != nil || t.Before(cutoff) {
			continue
		}
		s.evts = append(s.evts, e)
		// Seed topoBuf from loaded events so topology is correct after restart.
		s.updateTopoBuf(e, t)
	}
	s.evts = s.capBySeverity(s.evts)
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// capBySeverity enforces per-severity maximums, keeping newest events.
func (s *Store) capBySeverity(evts []Event) []Event {
	warnSlots, critSlots := s.cfg.MaxWarnings, s.cfg.MaxCriticals
	out := make([]Event, 0, len(evts))
	for _, e := range evts {
		if e.Severity == "critical" && critSlots > 0 {
			out = append(out, e)
			critSlots--
		} else if e.Severity == "warning" && warnSlots > 0 {
			out = append(out, e)
			warnSlots--
		}
	}
	return out
}

func (s *Store) flush() {
	// Increment generation under the lock (caller holds s.mu.Lock).
	s.flushGen++
	gen := s.flushGen
	snapshot := make([]Event, len(s.evts))
	copy(snapshot, s.evts)
	cfgSnap := s.cfg
	go func() {
		data, err := json.Marshal(eventFile{Events: snapshot, Retention: &cfgSnap})
		if err != nil {
			log.Printf("security-store: flush marshal: %v", err)
			return
		}
		tmp := s.path + ".tmp"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			log.Printf("security-store: flush write: %v", err)
			return
		}
		// Hold flushMu around the stale-check + rename so no newer goroutine
		// can interleave and have its rename overwritten by this one.
		s.flushMu.Lock()
		s.mu.RLock()
		stale := s.flushGen != gen
		s.mu.RUnlock()
		if stale {
			s.flushMu.Unlock()
			// Do NOT remove tmp here — a newer goroutine may have written
			// its data to the same .tmp path. Removing it would cause that
			// goroutine's subsequent Rename to fail with ENOENT.
			return
		}
		if err := os.Rename(tmp, s.path); err != nil {
			log.Printf("security-store: flush rename: %v", err)
		}
		s.flushMu.Unlock()
	}()
}

// Add ingests a Tetragon event: dedup, insert newest-first, cap, persist.
func (s *Store) Add(raw k8s.TetragonEvent) {
	if raw.Type != "kprobe" || raw.PolicyName == "" {
		return
	}
	severity := severityOf(raw)
	t, err := parseTime(raw.Time)
	if err != nil {
		t = time.Now().UTC()
	}

	s.mu.Lock()
	// Content-based dedup within 30s
	for i, e := range s.evts {
		if sameEvent(e, raw) {
			et, err2 := parseTime(e.Time)
			if err2 == nil && t.Sub(et).Abs() < dedupWindowSecs*time.Second {
				updated := e
				updated.Count++
				updated.Time = raw.Time
				s.evts = append(s.evts[:i], s.evts[i+1:]...)
				s.evts = append([]Event{updated}, s.evts...)
				s.updateTopoBuf(updated, t)
				s.flush()
				s.mu.Unlock()
				s.broadcast(updated)
				return
			}
		}
	}

	newEvt := Event{
		ID:         raw.Time + "-" + raw.Pod + "-" + raw.Binary + "-" + raw.PolicyName,
		Time:       raw.Time,
		Count:      1,
		Severity:   severity,
		Namespace:  raw.Namespace,
		Pod:        raw.Pod,
		Container:  raw.Container,
		NodeName:   raw.NodeName,
		Binary:     raw.Binary,
		Arguments:  raw.Arguments,
		ParentBin:  raw.ParentBin,
		Function:   raw.Function,
		PolicyName: raw.PolicyName,
		Action:     raw.Action,
		ProcessUID: raw.ProcessUID,
		FilePath:   raw.FilePath,
		FileOp:     raw.FileOp,
		NetDest:    raw.NetDest,
		NetSrc:     raw.NetSrc,
	}
	// Expire events older than TTL first, then cap — so cap sees only valid events
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.TTLDays)
	withNew := append([]Event{newEvt}, s.evts...)
	filtered := withNew[:0]
	for _, e := range withNew {
		if et, err2 := parseTime(e.Time); err2 == nil && et.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	s.evts = s.capBySeverity(filtered)

	// Update topology buffer — independent of event-count retention.
	s.updateTopoBuf(newEvt, t)

	// Lazy cleanup of stale topoBuf entries every 1000 adds.
	s.topoCleanup++
	if s.topoCleanup%1000 == 0 {
		for k, entry := range s.topoBuf {
			if !entry.LastSeen.After(cutoff) {
				delete(s.topoBuf, k)
			}
		}
	}

	s.flush()
	s.mu.Unlock()
	s.broadcast(newEvt)
}

func (s *Store) List() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]Event, len(s.evts))
	copy(cp, s.evts)
	return cp
}

// ListTopologyEvents returns the minimal event fields needed to build the
// network topology graph. Unlike List(), this is driven by topoBuf which is
// bounded by TTLDays (not by MaxWarnings/MaxCriticals), so blocked edges
// survive even when critical event retention is set very low.
func (s *Store) ListTopologyEvents() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.TTLDays)
	out := make([]Event, 0, len(s.topoBuf))
	for _, entry := range s.topoBuf {
		if entry.LastSeen.After(cutoff) {
			out = append(out, Event{
				Pod:       entry.Pod,
				Namespace: entry.Namespace,
				NodeName:  entry.NodeName,
				NetSrc:    entry.NetSrc,
				NetDest:   entry.NetDest,
				Action:    entry.Action,
				Function:  entry.Function,
			})
		}
	}
	return out
}

func (s *Store) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
		close(ch)
	}
}

func (s *Store) broadcast(e Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Run consumes Tetragon events from the shared broadcast.
func (s *Store) Run(ctx context.Context, k8sStore *k8s.Store) {
	ch, unsub := k8sStore.SubscribeTetragon()
	defer unsub()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			s.Add(evt)
		}
	}
}
