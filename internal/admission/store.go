package admission

import (
	"context"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Event represents a single VAP violation.
type Event struct {
	ID           string `json:"id"`
	Time         string `json:"time"`
	Namespace    string `json:"namespace"`
	InvolvedKind string `json:"involvedKind"` // from K8s Events watcher
	InvolvedName string `json:"involvedName"`
	Resource     string `json:"resource"`  // from webhook
	Name         string `json:"name"`       // from webhook
	Operation    string `json:"operation"`  // from webhook
	Username     string `json:"username"`   // from webhook
	PolicyName   string `json:"policyName"`
	BindingName  string `json:"bindingName"`
	Message      string `json:"message"`
	Source       string `json:"source"` // "webhook" or "k8s-event"
	RawMessage   string `json:"rawMessage,omitempty"`
}


const maxEvents = 500

// Store holds recent VAP violation events in a ring buffer.
type Store struct {
	mu     sync.RWMutex
	events []Event
	seen   map[string]struct{}    // deduplicate by event ID
	subs   map[chan Event]struct{} // per-subscriber channels for fanout
}

func NewStore() *Store {
	return &Store{
		events: make([]Event, 0, maxEvents),
		seen:   make(map[string]struct{}),
		subs:   make(map[chan Event]struct{}),
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
		default: // slow subscriber; drop rather than block
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
		Time:         t,
		Namespace:    e.InvolvedObject.Namespace,
		InvolvedKind: e.InvolvedObject.Kind,
		InvolvedName: e.InvolvedObject.Name,
		PolicyName:   policy,
		BindingName:  binding,
		Message:      violation,
		RawMessage:   e.Message,
		Source:       "k8s-event",
	}
	s.events = append([]Event{evt}, s.events...)
	if len(s.events) > maxEvents {
		for _, old := range s.events[maxEvents:] {
			delete(s.seen, old.ID)
		}
		s.events = s.events[:maxEvents]
	}
	s.mu.Unlock()

	s.broadcast(evt)
}

// Add appends a new event (from audit webhook) and trims to maxEvents.
func (s *Store) Add(e Event) {
	s.mu.Lock()
	if _, exists := s.seen[e.ID]; exists {
		s.mu.Unlock()
		return
	}
	s.seen[e.ID] = struct{}{}
	s.events = append([]Event{e}, s.events...)
	if len(s.events) > maxEvents {
		for _, old := range s.events[maxEvents:] {
			delete(s.seen, old.ID)
		}
		s.events = s.events[:maxEvents]
	}
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
