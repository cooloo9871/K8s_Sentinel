package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// WebhookPayload is the JSON body posted to webhook endpoints.
// The Text field is a human-readable summary compatible with Slack Incoming Webhooks (mrkdwn).
type WebhookPayload struct {
	Text       string  `json:"text"` // Slack-compatible summary (mrkdwn)
	RuleName   string  `json:"ruleName"`
	Severity   string  `json:"severity"`
	Time       string  `json:"time"`
	Namespace  string  `json:"namespace"`
	Pod        string  `json:"pod"`
	Container  string  `json:"container,omitempty"`
	NodeName   string  `json:"nodeName,omitempty"`
	Binary     string  `json:"binary,omitempty"`
	PolicyName string  `json:"policyName,omitempty"`
	Function   string  `json:"function,omitempty"`
	ProcessUID *uint32 `json:"processUid,omitempty"`
	FilePath   string  `json:"filePath,omitempty"`
	FileOp     string  `json:"fileOp,omitempty"`
	NetDest    string  `json:"netDest,omitempty"`
	NetSrc     string  `json:"netSrc,omitempty"`
}

func buildText(p WebhookPayload) string {
	icon := "⚠️"
	if p.Severity == "critical" {
		icon = "🔴"
	}
	lines := []string{
		fmt.Sprintf("%s *[%s]* %s", icon, strings.ToUpper(p.Severity), p.RuleName),
	}

	podLine := fmt.Sprintf("*Pod:* `%s/%s`", p.Namespace, p.Pod)
	if p.NodeName != "" {
		podLine += fmt.Sprintf("  •  *Node:* `%s`", p.NodeName)
	}
	lines = append(lines, podLine)

	if p.PolicyName != "" || p.Binary != "" {
		var parts []string
		if p.PolicyName != "" {
			parts = append(parts, fmt.Sprintf("*Policy:* `%s`", p.PolicyName))
		}
		if p.Binary != "" {
			parts = append(parts, fmt.Sprintf("*Binary:* `%s`", p.Binary))
		}
		lines = append(lines, strings.Join(parts, "  •  "))
	}

	if p.ProcessUID != nil {
		user := fmt.Sprintf("uid=%d", *p.ProcessUID)
		if *p.ProcessUID == 0 {
			user = "root (uid=0)"
		}
		lines = append(lines, fmt.Sprintf("*User:* %s", user))
	}

	if p.FilePath != "" {
		lines = append(lines, fmt.Sprintf("*File (%s):* `%s`", p.FileOp, p.FilePath))
	}

	if p.NetDest != "" {
		netLine := fmt.Sprintf("*Destination:* `%s`", p.NetDest)
		if p.NetSrc != "" {
			netLine += fmt.Sprintf("  •  *Source:* `%s`", p.NetSrc)
		}
		lines = append(lines, netLine)
	}

	return strings.Join(lines, "\n")
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
		NodeName:   evt.NodeName,
		Binary:     evt.Binary,
		PolicyName: evt.PolicyName,
		Function:   evt.Function,
		ProcessUID: evt.ProcessUID,
		FilePath:   evt.FilePath,
		FileOp:     evt.FileOp,
		NetDest:    evt.NetDest,
		NetSrc:     evt.NetSrc,
	}
	payload.Text = buildText(payload)
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
	payload.Text = buildText(payload)
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
