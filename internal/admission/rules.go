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
		ID:        fmt.Sprintf("rule-%d", time.Now().UnixMilli()),
		Name:      spec.Metadata.Name,
		Enabled:   true,
		Spec:      spec.Spec,
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
	existing.Name = spec.Metadata.Name
	existing.Spec = spec.Spec
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

// vapSpec is used for parsing name out of VAP-like YAML.
type vapSpec struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec RuleSpec `json:"spec"`
}

func parseSpec(rawYAML string) (vapSpec, error) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return vapSpec{}, fmt.Errorf("invalid YAML: %w", err)
	}
	var v vapSpec
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return vapSpec{}, fmt.Errorf("parse error: %w", err)
	}
	if len(v.Spec.Validations) == 0 {
		return vapSpec{}, fmt.Errorf("spec.validations must not be empty")
	}
	if v.Metadata.Name == "" {
		v.Metadata.Name = fmt.Sprintf("rule-%d", time.Now().UnixMilli())
	}
	return v, nil
}
