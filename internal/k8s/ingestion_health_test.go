package k8s

import (
	"fmt"
	"testing"
	"time"
)

// fixedClock returns a controllable now() for deterministic timestamps.
func fixedClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

func TestIngestionHealthConnectEventError(t *testing.T) {
	clock := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	h := NewIngestionHealth()
	h.now = fixedClock(&clock)

	h.MarkTetragonConnected("node-a")
	h.MarkTetragonEvent("node-a")
	h.MarkTetragonEvent("node-a")

	st, ok := h.TetragonStatus("node-a")
	if !ok {
		t.Fatal("node-a not recorded")
	}
	if !st.Connected {
		t.Error("node-a should be connected")
	}
	if st.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2", st.EventCount)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0", st.ConsecutiveFailures)
	}
	if st.LastEventAt == "" || st.LastConnectAt == "" {
		t.Error("connect/event timestamps should be set")
	}

	// A stream error marks it disconnected and starts the failure streak.
	clock = clock.Add(time.Minute)
	h.MarkTetragonError("node-a", fmt.Errorf("connection refused"))
	st, _ = h.TetragonStatus("node-a")
	if st.Connected {
		t.Error("node-a should be disconnected after an error")
	}
	if st.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", st.ConsecutiveFailures)
	}
	if st.LastError != "connection refused" {
		t.Errorf("LastError = %q, want %q", st.LastError, "connection refused")
	}

	// A second consecutive failure accumulates.
	h.MarkTetragonError("node-a", fmt.Errorf("connection refused"))
	st, _ = h.TetragonStatus("node-a")
	if st.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d, want 2", st.ConsecutiveFailures)
	}

	// Reconnecting clears the streak but keeps the cumulative event count.
	h.MarkTetragonConnected("node-a")
	st, _ = h.TetragonStatus("node-a")
	if !st.Connected || st.ConsecutiveFailures != 0 {
		t.Errorf("after reconnect: connected=%v failures=%d, want true/0", st.Connected, st.ConsecutiveFailures)
	}
	if st.EventCount != 2 {
		t.Errorf("EventCount after reconnect = %d, want 2 (cumulative)", st.EventCount)
	}
}

// A node whose very first attempt fails must still be recorded, so a
// never-reachable agent is visible rather than silently absent.
func TestIngestionHealthErrorBeforeAnyConnect(t *testing.T) {
	h := NewIngestionHealth()
	h.MarkTetragonError("node-b", fmt.Errorf("dial: i/o timeout"))
	st, ok := h.TetragonStatus("node-b")
	if !ok {
		t.Fatal("node-b not recorded after a first-attempt failure")
	}
	if st.Connected || st.ConsecutiveFailures != 1 {
		t.Errorf("node-b: connected=%v failures=%d, want false/1", st.Connected, st.ConsecutiveFailures)
	}
}

func TestIngestionHealthSnapshotOrder(t *testing.T) {
	h := NewIngestionHealth()
	h.MarkTetragonConnected("node-c")
	h.MarkTetragonConnected("node-a")
	h.MarkHubbleConnected()
	h.MarkHubbleEvent()

	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot has %d sources, want 3", len(snap))
	}
	// Tetragon nodes sorted by name, then Hubble last.
	want := []struct{ kind, name string }{
		{"tetragon", "node-a"},
		{"tetragon", "node-c"},
		{"hubble", "hubble"},
	}
	for i, w := range want {
		if snap[i].Kind != w.kind || snap[i].Name != w.name {
			t.Errorf("snap[%d] = %s/%s, want %s/%s", i, snap[i].Kind, snap[i].Name, w.kind, w.name)
		}
	}
}

// Hubble's connect point is its first flow, so an event alone must flip it to
// connected.
func TestIngestionHealthHubbleEventImpliesConnected(t *testing.T) {
	h := NewIngestionHealth()
	h.MarkHubbleEvent()
	snap := h.Snapshot()
	hubble := snap[len(snap)-1]
	if hubble.Kind != "hubble" || !hubble.Connected || hubble.EventCount != 1 {
		t.Errorf("hubble = %+v, want connected with 1 event", hubble)
	}
}

// Every method is safe on a nil receiver, so stream-path wiring never needs a
// guard.
func TestIngestionHealthNilSafe(t *testing.T) {
	var h *IngestionHealth
	h.MarkTetragonConnected("x")
	h.MarkTetragonError("x", fmt.Errorf("e"))
	h.MarkTetragonEvent("x")
	h.MarkHubbleConnected()
	h.MarkHubbleError(fmt.Errorf("e"))
	h.MarkHubbleEvent()
	if _, ok := h.TetragonStatus("x"); ok {
		t.Error("nil receiver should report nothing recorded")
	}
	if h.Snapshot() != nil {
		t.Error("nil receiver Snapshot should be nil")
	}
}

// A recovered source clears its failure streak on the next event, so it never
// shows connected-yet-failing.
func TestIngestionHealthEventClearsFailures(t *testing.T) {
	h := NewIngestionHealth()
	h.MarkTetragonError("node-a", fmt.Errorf("boom"))
	h.MarkTetragonEvent("node-a")
	st, _ := h.TetragonStatus("node-a")
	if !st.Connected || st.ConsecutiveFailures != 0 {
		t.Errorf("after event: connected=%v failures=%d, want true/0", st.Connected, st.ConsecutiveFailures)
	}
}

// PruneTetragon drops nodes no longer present and keeps the ones still alive.
func TestIngestionHealthPrune(t *testing.T) {
	h := NewIngestionHealth()
	h.MarkTetragonConnected("node-a")
	h.MarkTetragonConnected("node-b")
	h.PruneTetragon(map[string]bool{"node-a": true})
	if _, ok := h.TetragonStatus("node-a"); !ok {
		t.Error("node-a should be kept")
	}
	if _, ok := h.TetragonStatus("node-b"); ok {
		t.Error("node-b should have been pruned")
	}
}
