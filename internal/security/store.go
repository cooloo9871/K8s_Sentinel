package security

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

const (
	maxWarnings     = 500
	maxCriticals    = 300
	dedupWindowSecs = 30
	ttlDays         = 7
)

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
	Events []Event `json:"events"`
}

// Store holds Tetragon kprobe events with file persistence and SSE fanout.
type Store struct {
	mu        sync.RWMutex
	evts      []Event // newest-first
	subs      map[chan Event]struct{}
	path      string
	flushGen  uint64 // incremented each flush; goroutine skips write if stale
}

func NewStore(path string) *Store {
	s := &Store{
		evts: make([]Event, 0, maxWarnings+maxCriticals),
		subs: make(map[chan Event]struct{}),
		path: path,
	}
	s.load()
	return s
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
	cutoff := time.Now().UTC().AddDate(0, 0, -ttlDays)
	for _, e := range f.Events {
		t, err := parseTime(e.Time)
		if err != nil || t.Before(cutoff) {
			continue
		}
		s.evts = append(s.evts, e)
	}
	s.evts = capBySeverity(s.evts)
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// capBySeverity enforces per-severity maximums, keeping newest events.
func capBySeverity(evts []Event) []Event {
	warnSlots, critSlots := maxWarnings, maxCriticals
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
	go func() {
		data, err := json.Marshal(eventFile{Events: snapshot})
		if err != nil {
			log.Printf("security-store: flush marshal: %v", err)
			return
		}
		// Only write if no newer flush has been issued since this goroutine started.
		s.mu.RLock()
		stale := s.flushGen != gen
		s.mu.RUnlock()
		if stale {
			return
		}
		tmp := s.path + ".tmp"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			log.Printf("security-store: flush write: %v", err)
			return
		}
		if err := os.Rename(tmp, s.path); err != nil {
			log.Printf("security-store: flush rename: %v", err)
		}
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
	s.evts = capBySeverity(append([]Event{newEvt}, s.evts...))

	// Expire events older than TTL
	cutoff := time.Now().UTC().AddDate(0, 0, -ttlDays)
	filtered := s.evts[:0]
	for _, e := range s.evts {
		if et, err2 := parseTime(e.Time); err2 == nil && et.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	s.evts = filtered

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

// Run streams Tetragon events into the store. Reconnects automatically.
func (s *Store) Run(ctx context.Context, k8sStore *k8s.Store) {
	for {
		if ctx.Err() != nil {
			return
		}
		events := make(chan k8s.TetragonEvent, 256)
		go func() {
			defer close(events)
			if err := k8sStore.StreamTetragonEvents(ctx, events); err != nil && ctx.Err() == nil {
				log.Printf("security-store: stream error: %v", err)
			}
		}()
		for evt := range events {
			s.Add(evt)
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}
