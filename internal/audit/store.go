// Package audit records the administrative actions taken through Sentinel —
// who quarantined a pod, who changed Protect mode, who deleted a policy — so a
// security console can answer "who did what, when" about its own use. Every
// state-changing admin request is recorded by middleware, not per-handler, so
// a new write route cannot be forgotten.
package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// Entry is one recorded admin action.
type Entry struct {
	ID     string `json:"id"`
	Time   string `json:"time"`
	User   string `json:"user"`
	Action string `json:"action"` // human-readable, e.g. "Quarantine pod"
	Target string `json:"target,omitempty"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// maxEntries bounds the log. An audit trail must not be trivially floodable to
// evict evidence, so the cap is generous; the oldest are dropped past it.
const maxEntries = 5000

type auditFile struct {
	Entries []Entry `json:"entries"`
}

// Store is an append-only, persisted audit log.
type Store struct {
	mu      sync.RWMutex
	path    string
	entries []Entry // newest last
	seq     uint64  // monotonic, for unique IDs without a clock dependency
}

func NewStore(path string) *Store {
	s := &Store{path: path}
	s.load()
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f auditFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	s.entries = f.Entries
	s.seq = uint64(len(f.Entries))
}

// Record appends an entry, stamping it with the time and a unique ID. The user
// is whatever the middleware resolved; an empty user means the request reached
// here without a session, which should not happen on the admin group but is
// recorded honestly rather than dropped.
func (s *Store) Record(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.ID = e.Time + "-" + itoa(s.seq)
	s.entries = append(s.entries, e)
	if len(s.entries) > maxEntries {
		s.entries = s.entries[len(s.entries)-maxEntries:]
	}
	s.flush()
}

// List returns the log newest-first, which is how it is read.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[len(s.entries)-1-i] = e
	}
	return out
}

// flush persists under the held lock. Admin actions are infrequent, so a
// synchronous write per action is fine and avoids the snapshot dance the
// high-volume event stores need.
func (s *Store) flush() {
	data, err := json.Marshal(auditFile{Entries: s.entries})
	if err != nil {
		log.Printf("audit: flush marshal error: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("audit: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("audit: flush rename error: %v", err)
	}
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
