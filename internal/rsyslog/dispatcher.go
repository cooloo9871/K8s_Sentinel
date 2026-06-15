package rsyslog

import (
	"context"
	"fmt"
	gosyslog "log/syslog"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cooloo9871/sentinel/internal/k8s"
)

// Dispatcher streams Tetragon events and forwards matching ones to rsyslog servers.
type Dispatcher struct {
	store   *Store
	k8s     *k8s.Store
	mu      sync.Mutex
	writers map[string]*gosyslog.Writer // keyed by config ID
}

func NewDispatcher(store *Store, k8s *k8s.Store) *Dispatcher {
	return &Dispatcher{
		store:   store,
		k8s:     k8s,
		writers: make(map[string]*gosyslog.Writer),
	}
}

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
			log.Printf("rsyslog-dispatcher: stream error: %v", err)
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
	for _, cfg := range d.store.EnabledConfigs() {
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
		return w, nil
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

// TestSend opens a one-shot connection and sends a test message.
func (d *Dispatcher) TestSend(cfg Config) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	priority := gosyslog.Priority(cfg.Facility*8) | gosyslog.LOG_NOTICE
	w, err := gosyslog.Dial(cfg.Protocol, addr, priority, "sentinel")
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	defer w.Close()
	return w.Notice("sentinel test message from Sentinel dashboard")
}

func buildMessage(evt k8s.TetragonEvent, severity string) string {
	parts := []string{
		fmt.Sprintf("severity=%s", strings.ToUpper(severity)),
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
