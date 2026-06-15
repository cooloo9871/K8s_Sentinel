package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// WebhookPayload is the JSON body posted to webhook endpoints.
type WebhookPayload struct {
	RuleName   string `json:"ruleName"`
	Severity   string `json:"severity"`
	Time       string `json:"time"`
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container,omitempty"`
	Binary     string `json:"binary,omitempty"`
	PolicyName string `json:"policyName,omitempty"`
	Function   string `json:"function,omitempty"`
	FilePath   string `json:"filePath,omitempty"`
	FileOp     string `json:"fileOp,omitempty"`
	NetDest    string `json:"netDest,omitempty"`
	NetSrc     string `json:"netSrc,omitempty"`
}

// Dispatcher watches the Tetragon event stream and fires webhook alerts.
type Dispatcher struct {
	store  *Store
	k8s    *k8s.Store
	mu     sync.Mutex
	last   map[string]time.Time // cooldown tracking
	client *http.Client
}

func NewDispatcher(store *Store, k8s *k8s.Store) *Dispatcher {
	return &Dispatcher{
		store:  store,
		k8s:    k8s,
		last:   make(map[string]time.Time),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Run streams Tetragon events and dispatches alerts. Reconnects automatically.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		d.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (d *Dispatcher) runOnce(ctx context.Context) {
	events := make(chan k8s.TetragonEvent, 256)
	go func() {
		defer close(events)
		if err := d.k8s.StreamTetragonEvents(ctx, events); err != nil && ctx.Err() == nil {
			log.Printf("alert-dispatcher: stream error: %v", err)
		}
	}()
	for evt := range events {
		if evt.Type != "kprobe" || evt.PolicyName == "" {
			continue
		}
		d.dispatch(evt)
	}
}

func (d *Dispatcher) dispatch(evt k8s.TetragonEvent) {
	severity := "warning"
	if evt.Action == "kill" {
		severity = "critical"
	}

	rules := d.store.EnabledRules()
	for _, rule := range rules {
		if !rule.Matches(severity, evt.Namespace, evt.PolicyName) {
			continue
		}
		key := CooldownKey(rule.ID, evt.Namespace, evt.Pod, evt.Function, evt.PolicyName)
		d.mu.Lock()
		skip := WithinCooldown(d.last, key, rule.CooldownMin)
		if !skip {
			d.last[key] = time.Now()
		}
		d.mu.Unlock()
		if skip {
			continue
		}
		go d.post(rule, evt, severity)
	}
}

func (d *Dispatcher) post(rule AlertRule, evt k8s.TetragonEvent, severity string) {
	payload := WebhookPayload{
		RuleName:   rule.Name,
		Severity:   severity,
		Time:       evt.Time,
		Namespace:  evt.Namespace,
		Pod:        evt.Pod,
		Container:  evt.Container,
		Binary:     evt.Binary,
		PolicyName: evt.PolicyName,
		Function:   evt.Function,
		FilePath:   evt.FilePath,
		FileOp:     evt.FileOp,
		NetDest:    evt.NetDest,
		NetSrc:     evt.NetSrc,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("alert-dispatcher: marshal error: %v", err)
		return
	}
	resp, err := d.client.Post(rule.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alert-dispatcher: POST %q error: %v", rule.WebhookURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("alert-dispatcher: POST %q returned %d", rule.WebhookURL, resp.StatusCode)
	}
}

// SendTest posts a sample payload to the given URL for validation.
func (d *Dispatcher) SendTest(webhookURL string) error {
	payload := WebhookPayload{
		RuleName:   "Test Alert",
		Severity:   "critical",
		Time:       time.Now().UTC().Format(time.RFC3339),
		Namespace:  "default",
		Pod:        "example-pod-abc12",
		Binary:     "/bin/bash",
		PolicyName: "monitor-all-exec",
		Function:   "sys_execve",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := d.client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
