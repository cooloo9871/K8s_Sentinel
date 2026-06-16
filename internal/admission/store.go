package admission

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const dedupWindowSecs = 30

// Event represents a single VAP violation.
type Event struct {
	ID           string `json:"id"`
	Time         string `json:"time"`
	Count        int    `json:"count"`
	Namespace    string `json:"namespace"`
	InvolvedKind string `json:"involvedKind"` // from K8s Events watcher
	InvolvedName string `json:"involvedName"`
	Resource     string `json:"resource"`   // from webhook
	Name         string `json:"name"`        // from webhook
	Operation    string `json:"operation"`   // from webhook
	Username     string `json:"username"`    // from webhook
	PolicyName   string `json:"policyName"`
	BindingName  string `json:"bindingName"`
	Message      string `json:"message"`
	Severity     string `json:"severity"` // "critical" (Deny) or "warning" (Audit/Warn)
	Source       string `json:"source"`   // "audit" or "k8s-event"
	RawMessage   string `json:"rawMessage,omitempty"`
}

func sameViolation(a, b Event) bool {
	return a.PolicyName == b.PolicyName &&
		a.Namespace == b.Namespace &&
		a.Name == b.Name &&
		a.InvolvedName == b.InvolvedName &&
		a.Operation == b.Operation &&
		a.Source == b.Source
}

func timeDiffSecs(t1, t2 string) float64 {
	d1, err1 := time.Parse(time.RFC3339, t1)
	d2, err2 := time.Parse(time.RFC3339, t2)
	if err1 != nil || err2 != nil {
		return 9999
	}
	diff := d1.Sub(d2)
	if diff < 0 {
		diff = -diff
	}
	return diff.Seconds()
}

type eventFile struct {
	Events []Event `json:"events"`
}

const maxEvents = 500

// Store holds VAP violation events in a ring buffer with file persistence.
type Store struct {
	mu     sync.RWMutex
	events []Event
	seen   map[string]struct{}    // deduplicate by event ID
	subs   map[chan Event]struct{} // per-subscriber channels for fanout
	path   string                 // file path for persistence
}

func NewStore(path string) *Store {
	s := &Store{
		events: make([]Event, 0, maxEvents),
		seen:   make(map[string]struct{}),
		subs:   make(map[chan Event]struct{}),
		path:   path,
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
	for _, e := range f.Events {
		if _, exists := s.seen[e.ID]; !exists {
			s.seen[e.ID] = struct{}{}
			s.events = append(s.events, e)
		}
	}
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	// Ensure newest-first order after loading
	sortEventsDesc(s.events)
}

// sortEventsDesc sorts events newest-first in place.
func sortEventsDesc(events []Event) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0; j-- {
			if timeDiffSecs(events[j].Time, events[j-1].Time) > 0 {
				// events[j] is newer than events[j-1], swap
				events[j], events[j-1] = events[j-1], events[j]
			} else {
				break
			}
		}
	}
}

// insertSorted inserts evt into s.events maintaining newest-first order.
func (s *Store) insertSorted(evt Event) {
	evtT, err := time.Parse(time.RFC3339, evt.Time)
	if err != nil {
		s.events = append([]Event{evt}, s.events...)
		return
	}
	for i, existing := range s.events {
		exT, err2 := time.Parse(time.RFC3339, existing.Time)
		if err2 != nil || !evtT.Before(exT) {
			// Insert at position i
			s.events = append(s.events, Event{})
			copy(s.events[i+1:], s.events[i:])
			s.events[i] = evt
			return
		}
	}
	s.events = append(s.events, evt)
}

func (s *Store) flush() {
	data, err := json.Marshal(eventFile{Events: s.events})
	if err != nil {
		log.Printf("admission-store: flush marshal error: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("admission-store: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("admission-store: flush rename error: %v", err)
	}
}

// Subscribe returns a per-subscriber channel and an unsubscribe function.
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

// broadcast sends the event to all registered subscribers (non-blocking).
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

// Run watches K8s Warning events and captures VAP violations. Reconnects automatically.
func (s *Store) Run(ctx context.Context, typed kubernetes.Interface) {
	for {
		if ctx.Err() != nil {
			return
		}
		s.watchOnce(ctx, typed)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *Store) watchOnce(ctx context.Context, typed kubernetes.Interface) {
	watcher, err := typed.CoreV1().Events("").Watch(ctx, metav1.ListOptions{
		FieldSelector: "type=Warning",
	})
	if err != nil {
		log.Printf("admission-watcher: watch error: %v", err)
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case res, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			e, ok := res.Object.(*corev1.Event)
			if !ok {
				continue
			}
			if !strings.Contains(e.Message, "ValidatingAdmissionPolicy") {
				continue
			}
			s.addFromK8sEvent(e)
		}
	}
}

func (s *Store) addFromK8sEvent(e *corev1.Event) {
	uid := string(e.UID)
	s.mu.Lock()
	if _, exists := s.seen[uid]; exists {
		s.mu.Unlock()
		return
	}
	s.seen[uid] = struct{}{}

	t := e.LastTimestamp.UTC().Format(time.RFC3339)
	if t == "" || e.LastTimestamp.IsZero() {
		t = time.Now().UTC().Format(time.RFC3339)
	}
	policy, binding, violation := ParseVAPMessage(e.Message)
	evt := Event{
		ID:           uid,
		Count:        1,
		Time:         t,
		Namespace:    e.InvolvedObject.Namespace,
		InvolvedKind: e.InvolvedObject.Kind,
		InvolvedName: e.InvolvedObject.Name,
		PolicyName:   policy,
		BindingName:  binding,
		Message:      violation,
		Severity:     "critical",
		RawMessage:   e.Message,
		Source:       "k8s-event",
	}

	// Content-based dedup within 30s (K8s may create new UIDs for the same retry)
	for i, existing := range s.events {
		if sameViolation(existing, evt) && timeDiffSecs(evt.Time, existing.Time) < dedupWindowSecs {
			updated := existing
			updated.Count++
			updated.Time = evt.Time
			s.events = append([]Event{updated}, append(s.events[:i], s.events[i+1:]...)...)
			s.flush()
			s.mu.Unlock()
			s.broadcast(updated)
			return
		}
	}

	s.insertSorted(evt)
	if len(s.events) > maxEvents {
		for _, old := range s.events[maxEvents:] {
			delete(s.seen, old.ID)
		}
		s.events = s.events[:maxEvents]
	}
	s.flush()
	s.mu.Unlock()

	s.broadcast(evt)
}

// Add appends a new event (from audit webhook) with 30s deduplication.
func (s *Store) Add(e Event) {
	if e.Count == 0 {
		e.Count = 1
	}
	s.mu.Lock()
	if _, exists := s.seen[e.ID]; exists {
		s.mu.Unlock()
		return
	}
	// Dedup: if same violation within dedupWindowSecs, increment count and move to top
	for i, existing := range s.events {
		if sameViolation(existing, e) && timeDiffSecs(e.Time, existing.Time) < dedupWindowSecs {
			updated := existing
			updated.Count++
			updated.Time = e.Time
			updated.Operation = e.Operation // update to latest verb
			s.events = append([]Event{updated}, append(s.events[:i], s.events[i+1:]...)...)
			s.seen[e.ID] = struct{}{}
			s.flush()
			s.mu.Unlock()
			s.broadcast(updated)
			return
		}
	}
	s.seen[e.ID] = struct{}{}
	s.insertSorted(e)
	if len(s.events) > maxEvents {
		for _, old := range s.events[maxEvents:] {
			delete(s.seen, old.ID)
		}
		s.events = s.events[:maxEvents]
	}
	s.flush()
	s.mu.Unlock()
	s.broadcast(e)
}

// List returns all stored events (newest first).
func (s *Store) List() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]Event, len(s.events))
	copy(cp, s.events)
	return cp
}

var vapPattern = regexp.MustCompile(`ValidatingAdmissionPolicy '([^']+)' with binding '([^']+)'`)

// ParseVAPMessage extracts policyName, bindingName, and violation message from a K8s denial message.
func ParseVAPMessage(msg string) (policy, binding, violation string) {
	m := vapPattern.FindStringSubmatch(msg)
	if len(m) == 3 {
		policy, binding = m[1], m[2]
	}
	if idx := strings.Index(msg, "denied request: "); idx >= 0 {
		violation = msg[idx+len("denied request: "):]
	} else {
		violation = msg
	}
	return
}
