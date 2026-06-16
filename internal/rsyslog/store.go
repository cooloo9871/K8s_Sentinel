package rsyslog

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

type Config struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`       // default 514
	Protocol   string   `json:"protocol"`   // "udp" or "tcp"
	Facility   int      `json:"facility"`   // syslog facility number (16=local0 … 23=local7)
	EventTypes []string `json:"eventTypes"` // ["security","admission"], empty = all
	Severities []string `json:"severities"` // ["warning","critical"], empty = all
	Namespaces []string `json:"namespaces"` // empty = all
	Policies   []string `json:"policies"`   // empty = all
	Enabled    bool     `json:"enabled"`
}

type configFile struct {
	Configs []Config `json:"configs"`
}

type Store struct {
	mu      sync.RWMutex
	configs map[string]Config
	path    string
}

func NewStore(path string) *Store {
	s := &Store{path: path, configs: make(map[string]Config)}
	s.load()
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f configFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	for _, c := range f.Configs {
		s.configs[c.ID] = c
	}
}

func (s *Store) flush() {
	configs := make([]Config, 0, len(s.configs))
	for _, c := range s.configs {
		configs = append(configs, c)
	}
	data, err := json.Marshal(configFile{Configs: configs})
	if err != nil {
		log.Printf("rsyslog: flush marshal error: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("rsyslog: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("rsyslog: flush rename error: %v", err)
	}
}

func (s *Store) List() []Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Config, 0, len(s.configs))
	for _, c := range s.configs {
		out = append(out, c)
	}
	return out
}

func (s *Store) Create(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.configs[c.ID]; exists {
		return fmt.Errorf("config %q already exists", c.ID)
	}
	if c.Port == 0 {
		c.Port = 514
	}
	if c.Protocol == "" {
		c.Protocol = "udp"
	}
	s.configs[c.ID] = c
	s.flush()
	return nil
}

func (s *Store) Update(c Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.configs[c.ID]; !ok {
		return false
	}
	s.configs[c.ID] = c
	s.flush()
	return true
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.configs[id]; !ok {
		return false
	}
	delete(s.configs, id)
	s.flush()
	return true
}

func (s *Store) EnabledConfigs() []Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Config
	for _, c := range s.configs {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

func (c Config) MatchesEventType(eventType string) bool {
	if len(c.EventTypes) == 0 {
		return true
	}
	return contains(c.EventTypes, eventType)
}

func (c Config) Matches(severity, namespace, policy string) bool {
	if len(c.Severities) > 0 && !contains(c.Severities, severity) {
		return false
	}
	if len(c.Namespaces) > 0 && !contains(c.Namespaces, namespace) {
		return false
	}
	if len(c.Policies) > 0 && !contains(c.Policies, policy) {
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
