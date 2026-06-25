package rsyslog

import (
	"context"
	"fmt"
	gosyslog "log/syslog"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/k8s"
)

// Dispatcher streams Tetragon events and forwards matching ones to rsyslog servers.
type Dispatcher struct {
	store    *Store
	k8s      *k8s.Store
	admStore *admission.Store
	mu       sync.Mutex
	writers  map[string]*gosyslog.Writer // keyed by config ID
}

func NewDispatcher(store *Store, k8s *k8s.Store, admStore *admission.Store) *Dispatcher {
	return &Dispatcher{
		store:    store,
		k8s:      k8s,
		admStore: admStore,
		writers:  make(map[string]*gosyslog.Writer),
	}
}

func (d *Dispatcher) Run(ctx context.Context) {
	go d.runAdmission(ctx)
	go d.runTetragon(ctx)
}

func (d *Dispatcher) runTetragon(ctx context.Context) {
	ch, unsub := d.k8s.SubscribeTetragon()
	defer unsub()
	for {
		select {
		case <-ctx.Done():
			return
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

func (d *Dispatcher) dispatch(evt k8s.TetragonEvent) {
	severity := "warning"
	if evt.Action == "kill" {
		severity = "critical"
	}
	for _, cfg := range d.store.EnabledConfigs() {
		if !cfg.MatchesEventType("security") {
			continue
		}
		if !cfg.Matches(severity, evt.Namespace, evt.PolicyName) {
			continue
		}
		go d.send(cfg, evt, severity)
	}
}

func (d *Dispatcher) writer(cfg Config) (*gosyslog.Writer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if w, ok := d.writers[cfg.ID]; ok {
		// Invalidate cached writer if connection parameters have changed.
		if stored, found := d.store.Get(cfg.ID); found &&
			(stored.Host != cfg.Host || stored.Port != cfg.Port || stored.Protocol != cfg.Protocol) {
			w.Close()
			delete(d.writers, cfg.ID)
		} else {
			return w, nil
		}
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	priority := gosyslog.Priority(cfg.Facility*8) | gosyslog.LOG_WARNING
	w, err := gosyslog.Dial(cfg.Protocol, addr, priority, "sentinel")
	if err != nil {
		return nil, err
	}
	d.writers[cfg.ID] = w
	return w, nil
}

func (d *Dispatcher) invalidate(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if w, ok := d.writers[id]; ok {
		w.Close()
		delete(d.writers, id)
	}
}

func (d *Dispatcher) send(cfg Config, evt k8s.TetragonEvent, severity string) {
	w, err := d.writer(cfg)
	if err != nil {
		log.Printf("rsyslog-dispatcher: connect %s:%d error: %v", cfg.Host, cfg.Port, err)
		d.invalidate(cfg.ID)
		return
	}
	msg := buildMessage(evt, severity)
	var sendErr error
	if severity == "critical" {
		sendErr = w.Crit(msg)
	} else {
		sendErr = w.Warning(msg)
	}
	if sendErr != nil {
		log.Printf("rsyslog-dispatcher: send error: %v", sendErr)
		d.invalidate(cfg.ID)
	}
}

// TestSend opens a one-shot connection and sends a test message with a 5-second timeout.
func (d *Dispatcher) TestSend(cfg Config) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
		priority := gosyslog.Priority(cfg.Facility*8) | gosyslog.LOG_NOTICE
		w, err := gosyslog.Dial(cfg.Protocol, addr, priority, "sentinel")
		if err != nil {
			ch <- result{fmt.Errorf("connect %s: %w", addr, err)}
			return
		}
		defer w.Close()
		ch <- result{w.Notice("sentinel test message from Sentinel dashboard")}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("connection timed out after 5s — check host and port")
	}
}

func securityRuleType(fn string) string {
	if strings.Contains(fn, "tcp_connect") {
		return "network"
	}
	if strings.Contains(fn, "security_file") || strings.Contains(fn, "security_path") {
		return "file"
	}
	return "process"
}

func buildMessage(evt k8s.TetragonEvent, severity string) string {
	parts := []string{
		fmt.Sprintf("severity=%s", strings.ToUpper(severity)),
		fmt.Sprintf("type=%s", securityRuleType(evt.Function)),
		fmt.Sprintf("namespace=%s", evt.Namespace),
		fmt.Sprintf("pod=%s", evt.Pod),
	}
	if evt.PolicyName != "" {
		parts = append(parts, fmt.Sprintf("policy=%s", evt.PolicyName))
	}
	if evt.Binary != "" {
		parts = append(parts, fmt.Sprintf("binary=%s", evt.Binary))
	}
	if evt.NodeName != "" {
		parts = append(parts, fmt.Sprintf("node=%s", evt.NodeName))
	}
	if evt.ProcessUID != nil {
		if *evt.ProcessUID == 0 {
			parts = append(parts, "user=root")
		} else {
			parts = append(parts, fmt.Sprintf("user=uid=%d", *evt.ProcessUID))
		}
	}
	if evt.FilePath != "" {
		parts = append(parts, fmt.Sprintf("file_op=%s", evt.FileOp), fmt.Sprintf("file_path=%s", evt.FilePath))
	}
	if evt.NetDest != "" {
		parts = append(parts, fmt.Sprintf("dest=%s", evt.NetDest))
	}
	if evt.NetSrc != "" {
		parts = append(parts, fmt.Sprintf("src=%s", evt.NetSrc))
	}
	return strings.Join(parts, " ")
}

func (d *Dispatcher) runAdmission(ctx context.Context) {
	ch, unsub := d.admStore.Subscribe()
	defer unsub()
	for {
		select {
		case <-ctx.Done():
			return
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
	for _, cfg := range d.store.EnabledConfigs() {
		if !cfg.MatchesEventType("admission") {
			continue
		}
		if !cfg.Matches(severity, evt.Namespace, evt.PolicyName) {
			continue
		}
		go d.sendAdmission(cfg, evt, severity)
	}
}

func (d *Dispatcher) sendAdmission(cfg Config, evt admission.Event, severity string) {
	w, err := d.writer(cfg)
	if err != nil {
		log.Printf("rsyslog-dispatcher: admission connect %s:%d error: %v", cfg.Host, cfg.Port, err)
		d.invalidate(cfg.ID)
		return
	}
	msg := buildAdmissionMessage(evt, severity)
	var sendErr error
	if severity == "warning" {
		sendErr = w.Warning(msg)
	} else {
		sendErr = w.Crit(msg)
	}
	if sendErr != nil {
		log.Printf("rsyslog-dispatcher: admission send error: %v", sendErr)
		d.invalidate(cfg.ID)
	}
}

func buildAdmissionMessage(evt admission.Event, severity string) string {
	parts := []string{
		fmt.Sprintf("severity=%s", strings.ToUpper(severity)),
		"type=admission",
	}
	if evt.Namespace != "" {
		parts = append(parts, fmt.Sprintf("namespace=%s", evt.Namespace))
	}
	if evt.Resource != "" {
		parts = append(parts, fmt.Sprintf("resource=%s", evt.Resource))
	} else if evt.InvolvedKind != "" {
		parts = append(parts, fmt.Sprintf("resource=%ss", strings.ToLower(evt.InvolvedKind)))
	}
	name := evt.Name
	if name == "" {
		name = evt.InvolvedName
	}
	if name != "" {
		parts = append(parts, fmt.Sprintf("name=%s", name))
	}
	if evt.PolicyName != "" {
		parts = append(parts, fmt.Sprintf("policy=%s", evt.PolicyName))
	}
	if evt.BindingName != "" {
		parts = append(parts, fmt.Sprintf("binding=%s", evt.BindingName))
	}
	if evt.Operation != "" {
		parts = append(parts, fmt.Sprintf("action=%s", evt.Operation))
	}
	if evt.Username != "" {
		parts = append(parts, fmt.Sprintf("requestor=%q", evt.Username))
	}
	if evt.Message != "" {
		parts = append(parts, fmt.Sprintf("violation=%q", evt.Message))
	}
	return strings.Join(parts, " ")
}
