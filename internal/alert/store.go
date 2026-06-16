package alert

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type AlertRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	WebhookURL  string   `json:"webhookURL"`
	EventTypes  []string `json:"eventTypes"`  // ["security","admission"], empty = all
	Severities  []string `json:"severities"`  // ["warning","critical"], empty = all
	Namespaces  []string `json:"namespaces"`  // empty = all namespaces
	Policies    []string `json:"policies"`    // empty = all policies
	CooldownMin int      `json:"cooldownMin"` // minutes between repeat alerts, 0 = no cooldown
	Enabled     bool     `json:"enabled"`
}

type alertFile struct {
	Rules []AlertRule `json:"rules"`
}

type Store struct {
	mu    sync.RWMutex
	rules map[string]AlertRule
	path  string
}

func NewStore(path string) *Store {
	s := &Store{path: path, rules: make(map[string]AlertRule)}
	s.load()
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f alertFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	for _, r := range f.Rules {
		s.rules[r.ID] = r
	}
}

func (s *Store) flush() {
	rules := make([]AlertRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, r)
	}
	data, err := json.Marshal(alertFile{Rules: rules})
	if err != nil {
		log.Printf("alert: flush marshal error: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("alert: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("alert: flush rename error: %v", err)
	}
}

func (s *Store) List() []AlertRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]AlertRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, r)
	}
	return rules
}

func (s *Store) Get(id string) (AlertRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}

func (s *Store) Create(r AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rules[r.ID]; exists {
		return fmt.Errorf("rule %q already exists", r.ID)
	}
	s.rules[r.ID] = r
	s.flush()
	return nil
}

func (s *Store) Update(r AlertRule) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[r.ID]; !ok {
		return false
	}
	s.rules[r.ID] = r
	s.flush()
	return true
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	s.flush()
	return true
}

func (s *Store) EnabledRules() []AlertRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AlertRule
	for _, r := range s.rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

// MatchesEventType returns true if the event type is in the rule's eventTypes.
// Empty list means nothing matches (user must explicitly select event types).
func (r AlertRule) MatchesEventType(eventType string) bool {
	return contains(r.EventTypes, eventType)
}

// Matches returns true if the event matches the rule's filters.
// Empty severities means nothing matches (user must explicitly select severities).
func (r AlertRule) Matches(severity, namespace, policy string) bool {
	if !contains(r.Severities, severity) {
		return false
	}
	if len(r.Namespaces) > 0 && !contains(r.Namespaces, namespace) {
		return false
	}
	if len(r.Policies) > 0 && !contains(r.Policies, policy) {
		return false
	}
	return true
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// CooldownKey returns a dedup key combining rule ID and event identity.
func CooldownKey(ruleID, namespace, pod, function, policy string) string {
	return ruleID + "|" + namespace + "|" + pod + "|" + function + "|" + policy
}

// WithinCooldown reports whether the key was fired within the cooldown window.
func WithinCooldown(last map[string]time.Time, key string, cooldownMin int) bool {
	if cooldownMin <= 0 {
		return false
	}
	t, ok := last[key]
	if !ok {
		return false
	}
	return time.Since(t) < time.Duration(cooldownMin)*time.Minute
}
