package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// CustomTemplate is a user-created policy template stored on the pod filesystem.
type CustomTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	YAML        string   `json:"yaml"`
}

// TemplateStore persists custom templates to a JSON file.
type TemplateStore struct {
	mu       sync.RWMutex
	filePath string
	items    []CustomTemplate
}

func NewTemplateStore(filePath string) *TemplateStore {
	ts := &TemplateStore{filePath: filePath}
	ts.load()
	return ts
}

func (ts *TemplateStore) List() []CustomTemplate {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]CustomTemplate, len(ts.items))
	copy(out, ts.items)
	return out
}

func (ts *TemplateStore) Add(t CustomTemplate) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.items = append(ts.items, t)
	if err := ts.flush(); err != nil {
		fmt.Printf("[sentinel-templates] flush error: %v\n", err)
	}
}

func (ts *TemplateStore) Update(t CustomTemplate) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i, item := range ts.items {
		if item.ID == t.ID {
			ts.items[i] = t
			if err := ts.flush(); err != nil {
				fmt.Printf("[sentinel-templates] flush error: %v\n", err)
			}
			return true
		}
	}
	return false
}

func (ts *TemplateStore) Delete(id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	filtered := make([]CustomTemplate, 0, len(ts.items))
	for _, t := range ts.items {
		if t.ID != id {
			filtered = append(filtered, t)
		}
	}
	ts.items = filtered
	if err := ts.flush(); err != nil {
		fmt.Printf("[sentinel-templates] flush error: %v\n", err)
	}
}

func (ts *TemplateStore) flush() error {
	// Ensure parent directory exists.
	if err := os.MkdirAll(dirOf(ts.filePath), 0o755); err != nil {
		return err
	}
	tmp := ts.filePath + ".tmp"
	data, err := json.Marshal(ts.items)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, ts.filePath)
}

func (ts *TemplateStore) load() {
	data, err := os.ReadFile(ts.filePath)
	if err != nil {
		ts.items = []CustomTemplate{}
		return
	}
	var items []CustomTemplate
	if err := json.Unmarshal(data, &items); err != nil {
		ts.items = []CustomTemplate{}
		return
	}
	ts.items = items
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
