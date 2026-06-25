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

	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

// slackAttachment adds a colored left border in Slack (warning=yellow, danger=red).
type slackAttachment struct {
	Color    string   `json:"color"`
	Text     string   `json:"text"`
	MrkdwnIn []string `json:"mrkdwn_in"`
}

// WebhookPayload is the JSON body posted to webhook endpoints.
// Attachments provides Slack-specific colored formatting; Text is a plain fallback.
type WebhookPayload struct {
	Text        string            `json:"text"`                    // plain text fallback
	Attachments []slackAttachment `json:"attachments,omitempty"`   // Slack color + mrkdwn
	RuleName    string            `json:"ruleName"`
	Severity    string            `json:"severity"`
	Time        string            `json:"time"`
	Namespace   string            `json:"namespace"`
	Pod         string            `json:"pod"`
	Container   string            `json:"container,omitempty"`
	NodeName    string            `json:"nodeName,omitempty"`
	Binary      string            `json:"binary,omitempty"`
	PolicyName  string            `json:"policyName,omitempty"`
	Function    string            `json:"function,omitempty"`
	ProcessUID  *uint32           `json:"processUid,omitempty"`
	FilePath    string            `json:"filePath,omitempty"`
	FileOp      string            `json:"fileOp,omitempty"`
	NetDest     string            `json:"netDest,omitempty"`
	NetSrc      string            `json:"netSrc,omitempty"`
}

func ruleType(p WebhookPayload) string {
	if p.NetDest != "" || p.NetSrc != "" {
		return "Network Rule"
	}
	if p.FilePath != "" {
		return "File Rule"
	}
	return "Process Rule"
}

func buildSlackText(p WebhookPayload) string {
	lines := []string{
		fmt.Sprintf("*[%s]* %s", strings.ToUpper(p.Severity), p.RuleName),
		fmt.Sprintf("*Rule:* %s", ruleType(p)),
	}
	if p.PolicyName != "" {
		lines = append(lines, fmt.Sprintf("*Policy:* `%s`", p.PolicyName))
	}
	lines = append(lines, fmt.Sprintf("*Pod:* `%s/%s`", p.Namespace, p.Pod))
	if p.Binary != "" {
		lines = append(lines, fmt.Sprintf("*Binary:* `%s`", p.Binary))
	}
	if p.NodeName != "" {
		lines = append(lines, fmt.Sprintf("*Node:* `%s`", p.NodeName))
	}
	if p.ProcessUID != nil {
		user := fmt.Sprintf("`uid=%d`", *p.ProcessUID)
		if *p.ProcessUID == 0 {
			user = "`root (uid=0)`"
		}
		lines = append(lines, fmt.Sprintf("*User:* %s", user))
	}
	if p.FilePath != "" {
		lines = append(lines, fmt.Sprintf("*File (%s):* `%s`", p.FileOp, p.FilePath))
	}
	if p.NetDest != "" {
		lines = append(lines, fmt.Sprintf("*Destination:* `%s`", p.NetDest))
	}
	if p.NetSrc != "" {
		lines = append(lines, fmt.Sprintf("*Source:* `%s`", p.NetSrc))
	}
	return strings.Join(lines, "\n")
}

func buildPayload(p *WebhookPayload) {
	color := "warning" // yellow for warning
	if p.Severity == "critical" {
		color = "danger" // red for critical
	}
	text := buildSlackText(*p)
	p.Text = "" // outer text empty — attachment renders all content; avoids duplication
	p.Attachments = []slackAttachment{
		{Color: color, Text: text, MrkdwnIn: []string{"text"}},
	}
}

// Dispatcher watches the Tetragon event stream and fires webhook alerts.
type Dispatcher struct {
	store    *Store
	k8s      *k8s.Store
	admStore *admission.Store
	mu       sync.Mutex
	last     map[string]time.Time // cooldown tracking
	client   *http.Client
}

func NewDispatcher(store *Store, k8s *k8s.Store, admStore *admission.Store) *Dispatcher {
	return &Dispatcher{
		store:    store,
		k8s:      k8s,
		admStore: admStore,
		last:     make(map[string]time.Time),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// purgeCooldowns removes expired cooldown entries to prevent unbounded map growth.
func (d *Dispatcher) purgeCooldowns(rules []AlertRule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	maxCooldown := 0
	for _, r := range rules {
		if r.CooldownMin > maxCooldown {
			maxCooldown = r.CooldownMin
		}
	}
	cutoff := time.Duration(maxCooldown+1) * time.Minute
	for k, t := range d.last {
		if time.Since(t) > cutoff {
			delete(d.last, k)
		}
	}
}

// Run consumes Tetragon events from the shared broadcast and dispatches alerts.
func (d *Dispatcher) Run(ctx context.Context) {
	go d.runAdmission(ctx)
	go d.runTetragon(ctx)
}

func (d *Dispatcher) runTetragon(ctx context.Context) {
	ch, unsub := d.k8s.SubscribeTetragon()
	defer unsub()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.purgeCooldowns(d.store.EnabledRules())
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if evt.Type != "kprobe" || evt.PolicyName == "" {
				continue
			}
			d.dispatch(evt)
		}
	}
}

func (d *Dispatcher) runAdmission(ctx context.Context) {
	ch, unsub := d.admStore.Subscribe()
	defer unsub()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.purgeCooldowns(d.store.EnabledRules())
		case evt := <-ch:
			d.dispatchAdmission(evt)
		}
	}
}

func (d *Dispatcher) dispatchAdmission(evt admission.Event) {
	severity := evt.Severity
	if severity == "" {
		severity = "critical"
	}
	rules := d.store.EnabledRules()
	for _, rule := range rules {
		if !rule.MatchesEventType("admission") {
			continue
		}
		if !rule.Matches(severity, evt.Namespace, evt.PolicyName) {
			continue
		}
		evtName := evt.Name
		if evtName == "" {
			evtName = evt.InvolvedName
		}
		key := CooldownKey(rule.ID, evt.Namespace, evtName, "admission", evt.PolicyName)
		d.mu.Lock()
		skip := WithinCooldown(d.last, key, rule.CooldownMin)
		if !skip {
			d.last[key] = time.Now()
		}
		d.mu.Unlock()
		if skip {
			continue
		}
		go d.postAdmission(rule, evt, severity)
	}
}

func (d *Dispatcher) postAdmission(rule AlertRule, evt admission.Event, severity string) {
	lines := []string{
		fmt.Sprintf("*[%s]* %s", strings.ToUpper(severity), rule.Name),
		"*Rule:* Admission Event",
	}
	if evt.PolicyName != "" {
		lines = append(lines, fmt.Sprintf("*Policy:* `%s`", evt.PolicyName))
	}
	if evt.BindingName != "" {
		lines = append(lines, fmt.Sprintf("*Binding:* `%s`", evt.BindingName))
	}
	resource := evt.InvolvedName
	if evt.Name != "" {
		resource = evt.Name
	}
	ns := evt.Namespace
	if ns == "" {
		ns = "cluster-wide"
	}
	lines = append(lines, fmt.Sprintf("*Namespace:* `%s`", ns))
	if evt.Resource != "" && resource != "" {
		lines = append(lines, fmt.Sprintf("*Object:* `%s/%s`", evt.Resource, resource))
	} else if resource != "" {
		lines = append(lines, fmt.Sprintf("*Object:* `%s`", resource))
	}
	if evt.Operation != "" {
		lines = append(lines, fmt.Sprintf("*Action:* `%s`", evt.Operation))
	}
	if evt.Username != "" {
		lines = append(lines, fmt.Sprintf("*Requestor:* `%s`", evt.Username))
	}
	if evt.Message != "" {
		lines = append(lines, fmt.Sprintf("*Violation:* %s", evt.Message))
	}
	slackColor := "danger"
	if severity == "warning" {
		slackColor = "warning"
	}
	text := strings.Join(lines, "\n")
	payload := map[string]interface{}{
		"text": "",
		"attachments": []map[string]interface{}{
			{"color": slackColor, "text": text, "mrkdwn_in": []string{"text"}},
		},
		"ruleName":  rule.Name,
		"severity":  severity,
		"time":      evt.Time,
		"namespace": evt.Namespace,
		"policy":    evt.PolicyName,
		"binding":   evt.BindingName,
		"resource":  resource,
		"requestor": evt.Username,
		"message":   evt.Message,
	}
	if evt.Operation != "" {
		payload["action"] = evt.Operation
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	resp, err := d.client.Post(rule.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alert-dispatcher: admission POST %q error: %v", rule.WebhookURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("alert-dispatcher: admission POST %q returned %d", rule.WebhookURL, resp.StatusCode)
	}
}


func (d *Dispatcher) dispatch(evt k8s.TetragonEvent) {
	severity := "warning"
	if evt.Action == "kill" {
		severity = "critical"
	}

	rules := d.store.EnabledRules()
	for _, rule := range rules {
		if !rule.MatchesEventType("security") {
			continue
		}
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
	buildPayload(&payload)
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
	buildPayload(&payload)
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
