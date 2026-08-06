package security

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strconv"
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
	DropReason string  `json:"dropReason,omitempty"`
}

// collapseEphemeralPort replaces a client-side port with a fixed marker. The
// kernel picks a different one for every connection (Linux's default range
// starts at 32768), so comparing it verbatim made two attempts at the same
// denied destination look like unrelated events: dedup never matched, and a pod
// retrying in a loop filled the whole list with one repeated denial, evicting
// everything else through the retention cap.
//
// Used only for comparison — the stored event keeps the real port.
func collapseEphemeralPort(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr
	}
	if p, err := strconv.Atoi(addr[i+1:]); err == nil && p >= 32768 {
		return addr[:i+1] + "dynamic"
	}
	return addr
}

// Fingerprint renders what this store treats as one and the same event.
//
// It is exported because alerting and syslog forwarding have to agree with the
// events list about what a distinct event is. They used to answer that question
// separately and coarsely, so the console folded a hundred identical denials
// into one row while the webhook fired a hundred times — and, worse, an alert
// cooldown keyed only on the pod swallowed denials to *different* destinations
// as though they were repeats.
//
// The client-side port is collapsed because the kernel picks a fresh one per
// connection; comparing it verbatim would make every retry a new event.
func Fingerprint(e k8s.TetragonEvent) string {
	return strings.Join([]string{
		e.Namespace, e.Pod, e.Binary, e.Function, e.PolicyName, e.Action,
		e.FilePath, e.FileOp, e.NetDest, collapseEphemeralPort(e.NetSrc),
	}, "|")
}

// storedFingerprint is Fingerprint for an event already in the store. Kept next
// to it so the two shapes cannot describe identity differently.
func storedFingerprint(e Event) string {
	return strings.Join([]string{
		e.Namespace, e.Pod, e.Binary, e.Function, e.PolicyName, e.Action,
		e.FilePath, e.FileOp, e.NetDest, collapseEphemeralPort(e.NetSrc),
	}, "|")
}

func sameEvent(a Event, b k8s.TetragonEvent) bool {
	return storedFingerprint(a) == Fingerprint(b)
}

type eventFile struct {
	Events    []Event          `json:"events"`
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

// Store holds Tetragon kprobe events with file persistence and SSE fanout.
type Store struct {
	mu   sync.RWMutex
	evts []Event // newest-first
	subs map[chan Event]struct{}
	// Subscribers that want only the events that opened a new row. The SSE feed
	// needs every update so the count ticks; alerting and syslog want one
	// notification per distinct event, which is what the list shows.
	firstSubs map[chan k8s.TetragonEvent]struct{}
	path      string
	flushGen  uint64     // incremented each flush; goroutine skips write if stale
	flushMu   sync.Mutex // serialises the stale-check + rename to eliminate TOCTOU
	// Tracks flushes still in flight. Writing is asynchronous, which is right for
	// a long-lived process and invisible to it — but a test that ends while a
	// write is landing races with its own cleanup, so it needs a way to wait.
	flushWG sync.WaitGroup
	cfg     RetentionConfig
}

func NewStore(path string) *Store {
	cfg := DefaultRetentionConfig()
	s := &Store{
		evts:      make([]Event, 0, cfg.MaxWarnings+cfg.MaxCriticals),
		subs:      make(map[chan Event]struct{}),
		firstSubs: make(map[chan k8s.TetragonEvent]struct{}),
		path:      path,
		cfg:       cfg,
	}
	s.load()
	return s
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
	s.flushWG.Add(1)
	go func() {
		defer s.flushWG.Done()
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
	if !raw.IsSecurityEvent() {
		return
	}
	severity := raw.Severity()
	t, err := parseTime(raw.Time)
	if err != nil {
		// A timestamp this store cannot read poisons everything downstream: the
		// TTL filter below drops the event on the way in, the dedup window can
		// never match the row again so every repeat opens a new one, and the
		// first-sighting feed said it had been recorded regardless. Stamp it
		// with arrival time and carry on.
		t = time.Now().UTC()
		raw.Time = t.Format(time.RFC3339Nano)
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
				// Fill in what the stored copy is missing. Some fields become
				// known only later — the container name is resolved from the
				// Kubernetes API, and an L7 drop reason arrives on a different
				// flow than the L3/L4 one. A pod retrying in a loop refreshes
				// the same row indefinitely, so without this the first
				// sighting's gaps were permanent: a row recorded before the
				// container lookup existed could never acquire one.
				if updated.Container == "" {
					updated.Container = raw.Container
				}
				if updated.DropReason == "" {
					updated.DropReason = raw.DropReason
				}
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
		DropReason: raw.DropReason,
	}
	// Expire events older than TTL first, then cap — so cap sees only valid events
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.TTLDays)
	// Whether the store will actually keep this one. Both filters below can drop
	// it — an event older than the TTL, or a severity whose retention cap is zero
	// — and notifying about a row that does not exist is precisely the
	// divergence the first-sighting feed exists to prevent.
	slots := s.cfg.MaxWarnings
	if severity == "critical" {
		slots = s.cfg.MaxCriticals
	}
	recorded := t.After(cutoff) && slots > 0
	withNew := append([]Event{newEvt}, s.evts...)
	filtered := withNew[:0]
	for _, e := range withNew {
		if et, err2 := parseTime(e.Time); err2 == nil && et.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	s.evts = s.capBySeverity(filtered)

	s.flush()
	s.mu.Unlock()
	s.broadcast(newEvt)
	if recorded {
		s.broadcastFirst(raw)
	}
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

// SubscribeFirstSightings delivers each event the first time it is recorded.
// A repeat folded into an existing row does not appear — the row already stands
// for it, and a subscriber that acted on every occurrence would report a volume
// the events list contradicts.
func (s *Store) SubscribeFirstSightings() (<-chan k8s.TetragonEvent, func()) {
	ch := make(chan k8s.TetragonEvent, 256)
	s.mu.Lock()
	s.firstSubs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.firstSubs, ch)
		s.mu.Unlock()
		close(ch)
	}
}

func (s *Store) broadcastFirst(e k8s.TetragonEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.firstSubs {
		select {
		case ch <- e:
		default:
		}
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

// WaitForFlush blocks until every flush started so far has finished. Test-only:
// nothing in the running program needs it, and a test that ends mid-write would
// otherwise race with the removal of its own temporary directory.
func (s *Store) WaitForFlush() {
	s.flushWG.Wait()
}
