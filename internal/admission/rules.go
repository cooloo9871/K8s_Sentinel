package admission

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/yaml"
)

// ResourceRule matches specific K8s resources.
type ResourceRule struct {
	APIGroups   []string `json:"apiGroups"`
	APIVersions []string `json:"apiVersions"`
	Resources   []string `json:"resources"`
	Operations  []string `json:"operations"`
}

// Validation holds one CEL expression and its violation message.
type Validation struct {
	Expression string `json:"expression"`
	Message    string `json:"message,omitempty"`
}

// RuleSpec is the VAP-compatible spec section.
type RuleSpec struct {
	MatchConstraints struct {
		ResourceRules []ResourceRule `json:"resourceRules"`
	} `json:"matchConstraints"`
	Validations []Validation `json:"validations"`
}

// AdmissionRule is a Sentinel-managed admission rule.
type AdmissionRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Spec        RuleSpec `json:"spec"`
	RawYAML     string   `json:"rawYaml"`
	CreatedAt   string   `json:"createdAt"`
}

type ruleFile struct {
	Rules []AdmissionRule `json:"rules"`
}

// RuleStore manages Sentinel admission rules with file persistence.
type RuleStore struct {
	mu    sync.RWMutex
	rules map[string]AdmissionRule
	path  string
}

func NewRuleStore(path string) *RuleStore {
	s := &RuleStore{path: path, rules: make(map[string]AdmissionRule)}
	s.load()
	return s
}

func (s *RuleStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f ruleFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	for _, r := range f.Rules {
		s.rules[r.ID] = r
	}
}

func (s *RuleStore) flush() {
	rules := make([]AdmissionRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, r)
	}
	data, err := json.Marshal(ruleFile{Rules: rules})
	if err != nil {
		log.Printf("admission-rules: flush marshal error: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("admission-rules: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("admission-rules: flush rename error: %v", err)
	}
}

func (s *RuleStore) List() []AdmissionRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AdmissionRule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out
}

func (s *RuleStore) EnabledRules() []AdmissionRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AdmissionRule
	for _, r := range s.rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func (s *RuleStore) Create(rawYAML string) (AdmissionRule, error) {
	spec, err := parseSpec(rawYAML)
	if err != nil {
		return AdmissionRule{}, err
	}
	r := AdmissionRule{
		ID:          fmt.Sprintf("rule-%d", time.Now().UnixMilli()),
		Name:        spec.Name,
		Description: spec.Description,
		Enabled:     true,
		Spec: RuleSpec{
			MatchConstraints: spec.MatchConstraints,
			Validations:      spec.Validations,
		},
		RawYAML:   rawYAML,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.mu.Lock()
	s.rules[r.ID] = r
	s.flush()
	s.mu.Unlock()
	return r, nil
}

func (s *RuleStore) Update(id, rawYAML string) (AdmissionRule, error) {
	spec, err := parseSpec(rawYAML)
	if err != nil {
		return AdmissionRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.rules[id]
	if !ok {
		return AdmissionRule{}, fmt.Errorf("rule %q not found", id)
	}
	existing.Name = spec.Name
	existing.Description = spec.Description
	existing.Spec = RuleSpec{
		MatchConstraints: spec.MatchConstraints,
		Validations:      spec.Validations,
	}
	existing.RawYAML = rawYAML
	s.rules[id] = existing
	s.flush()
	return existing, nil
}

func (s *RuleStore) SetEnabled(id string, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return false
	}
	r.Enabled = enabled
	s.rules[id] = r
	s.flush()
	return true
}

func (s *RuleStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	s.flush()
	return true
}

// sentinelRule is the Sentinel-native rule format (flat, no apiVersion/kind/metadata).
type sentinelRule struct {
	Name             string           `json:"name"`
	Description      string           `json:"description,omitempty"`
	MatchConstraints MatchConstraints `json:"matchConstraints"`
	Validations      []Validation     `json:"validations"`
}

func parseSpec(rawYAML string) (sentinelRule, error) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return sentinelRule{}, fmt.Errorf("invalid YAML: %w", err)
	}
	var v sentinelRule
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return sentinelRule{}, fmt.Errorf("parse error: %w", err)
	}
	if len(v.Validations) == 0 {
		return sentinelRule{}, fmt.Errorf("validations must not be empty")
	}
	if v.Name == "" {
		v.Name = fmt.Sprintf("rule-%d", time.Now().UnixMilli())
	}
	return v, nil
}
