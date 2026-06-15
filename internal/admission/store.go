package admission

import (
	"regexp"
	"sync"
)

// Event represents a single VAP violation captured from the K8s audit webhook.
type Event struct {
	ID          string `json:"id"`
	Time        string `json:"time"`
	Username    string `json:"username"`
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	PolicyName  string `json:"policyName"`
	BindingName string `json:"bindingName"`
	Message     string `json:"message"`
}

const maxEvents = 500

// Store holds recent VAP admission violation events in a ring buffer.
type Store struct {
	mu     sync.RWMutex
	events []Event
	ch     chan Event
}

func NewStore() *Store {
	return &Store{
		events: make([]Event, 0, maxEvents),
		ch:     make(chan Event, 256),
	}
}

// Add appends a new event and trims to maxEvents.
func (s *Store) Add(e Event) {
	s.mu.Lock()
	s.events = append([]Event{e}, s.events...)
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	s.mu.Unlock()
	select {
	case s.ch <- e:
	default:
	}
}

// List returns all stored events (newest first).
func (s *Store) List() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]Event, len(s.events))
	copy(cp, s.events)
	return cp
}

// Subscribe returns the broadcast channel for new events.
func (s *Store) Subscribe() <-chan Event {
	return s.ch
}

// vapPattern extracts policy and binding names from the K8s denial message.
// Example: "ValidatingAdmissionPolicy 'demo-policy' with binding 'demo-binding' denied request: ..."
var vapPattern = regexp.MustCompile(`ValidatingAdmissionPolicy '([^']+)' with binding '([^']+)'`)

// ParseVAPMessage extracts policyName, bindingName, and violation message.
func ParseVAPMessage(msg string) (policy, binding, violation string) {
	m := vapPattern.FindStringSubmatch(msg)
	if len(m) == 3 {
		policy, binding = m[1], m[2]
	}
	// Extract the part after "denied request: "
	if idx := indexOf(msg, "denied request: "); idx >= 0 {
		violation = msg[idx+len("denied request: "):]
	} else {
		violation = msg
	}
	return
}

func indexOf(s, sub string) int {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
