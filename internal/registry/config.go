// Package registry scans the images in container registries for known
// vulnerabilities, before anything deploys them. Trivy does the scanning, in a
// Job per image; this package decides which images, starts the Jobs, and keeps
// what they found.
package registry

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	TypeDocker = "docker"
	TypeHarbor = "harbor"
	TypeQuay   = "quay"

	minIntervalDays = 1
	maxIntervalDays = 30
	maxCACertBytes  = 256 << 10
)

// Config is one registry and what to scan in it.
type Config struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// "docker" | "harbor" | "quay": how repositories are listed. Tags are
	// listed the same way on all three.
	Type string `json:"type"`
	// Scheme and host, e.g. https://harbor.internal:8443.
	URL      string `json:"url"`
	Username string `json:"username"`
	// Never sent to the browser; see Public.
	Password string `json:"password,omitempty"`
	// "repository[:tag]" with * as a wildcard: library/*, team/app:v1.*
	Filters       []string `json:"filters"`
	IntervalDays  int      `json:"intervalDays"`
	SkipTLSVerify bool     `json:"skipTLSVerify"`
	// PEM certificates to trust for this registry in addition to the public
	// ones: the CA that signed a private registry's certificate. Not a secret.
	CACert string `json:"caCert"`
}

// PublicConfig is a Config as the API returns it.
type PublicConfig struct {
	Config
	HasPassword bool `json:"hasPassword"`
}

// Public strips the password, leaving only whether one is set.
func (c Config) Public() PublicConfig {
	p := PublicConfig{Config: c, HasPassword: c.Password != ""}
	p.Password = ""
	return p
}

// Validate normalises a Config and reports what is wrong with it.
func (c *Config) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
	c.Username = strings.TrimSpace(c.Username)
	if c.Name == "" {
		return errors.New("name is required")
	}
	switch c.Type {
	case TypeDocker, TypeHarbor, TypeQuay:
	default:
		return errors.New("type must be docker, harbor or quay")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return errors.New("url must be http:// or https:// followed by the registry host, with no path")
	}
	if c.Username == "" {
		c.Password = ""
	}
	filters := make([]string, 0, len(c.Filters))
	for _, f := range c.Filters {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		pf, err := parseFilter(f)
		if err != nil {
			return err
		}
		if c.Type != TypeDocker && strings.Contains(pf.repo, "*") {
			if project, _, ok := strings.Cut(pf.repo, "/"); !ok || strings.Contains(project, "*") {
				return fmt.Errorf("filter %q: name the project before the wildcard, as in library/*", f)
			}
		}
		filters = append(filters, f)
	}
	if len(filters) == 0 {
		return errors.New("at least one filter is required")
	}
	c.Filters = filters
	c.CACert = strings.TrimSpace(c.CACert)
	if c.CACert != "" {
		if len(c.CACert) > maxCACertBytes {
			return errors.New("the CA certificate is too large")
		}
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACert)) {
			return errors.New("the CA certificate is not a PEM certificate; paste the file's contents, starting with -----BEGIN CERTIFICATE-----")
		}
		c.CACert += "\n"
	}
	if c.IntervalDays < minIntervalDays || c.IntervalDays > maxIntervalDays {
		return fmt.Errorf("interval must be %d to %d days", minIntervalDays, maxIntervalDays)
	}
	return nil
}

// Host is the registry as it appears in an image reference.
func (c Config) Host() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	return u.Host
}

// Store keeps the registries in a file, like the other settings.
type Store struct {
	mu      sync.RWMutex
	configs map[string]Config
	path    string
}

func NewStore(path string) *Store {
	s := &Store{path: path, configs: map[string]Config{}}
	if data, err := os.ReadFile(path); err == nil {
		var list []Config
		if err := json.Unmarshal(data, &list); err != nil {
			log.Printf("registry: %s is unreadable: %v", path, err)
		}
		for _, c := range list {
			s.configs[c.ID] = c
		}
	}
	return s
}

func (s *Store) flush() {
	if err := writeJSON(s.path, s.sorted()); err != nil {
		log.Printf("registry: saving registries: %v", err)
	}
}

func (s *Store) sorted() []Config {
	out := make([]Config, 0, len(s.configs))
	for _, c := range s.configs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) List() []Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sorted()
}

func (s *Store) Get(id string) (Config, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.configs[id]
	return c, ok
}

func (s *Store) Create(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[c.ID] = c
	s.flush()
}

// Update replaces a registry. An empty password keeps the stored one, since the
// form never receives it back; Validate has already cleared it when the
// username was removed.
func (s *Store) Update(c Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.configs[c.ID]
	if !ok {
		return false
	}
	if c.Password == "" && c.Username != "" {
		c.Password = old.Password
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

// writeJSON replaces a file in one step, so a crash never leaves half of one.
func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
