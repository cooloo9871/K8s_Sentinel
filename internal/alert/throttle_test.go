package alert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestDispatcher is the minimum needed to exercise the send path in
// isolation, without a Store or event subscriptions.
func newTestDispatcher() *Dispatcher {
	return &Dispatcher{
		client:   &http.Client{Timeout: 2 * time.Second},
		queue:    make(chan queuedSend, sendQueueSize),
		nextSend: make(map[string]time.Time),
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"5", 5 * time.Second},
		{"0", 0},
		{"", 0},
		{"not-a-number", 0},
		{"  3 ", 3 * time.Second},
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in); got != c.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// An HTTP date in the future yields a positive duration.
	future := time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > 21*time.Second {
		t.Errorf("parseRetryAfter(future date) = %v, want ~20s", got)
	}
}

// A 429 is retried (honouring the absence of Retry-After via backoff) and the
// alert eventually gets through rather than being dropped on the first refusal.
func TestDeliverRetriesOn429ThenSucceeds(t *testing.T) {
	old := baseBackoff
	baseBackoff = time.Millisecond
	defer func() { baseBackoff = old }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := newTestDispatcher()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("server was hit %d times, want 3 (two 429s then success)", got)
	}
}

// A destination that never recovers is retried a bounded number of times and
// then given up on, so it cannot block the queue forever.
func TestDeliverGivesUpAfterMaxRetries(t *testing.T) {
	old := baseBackoff
	baseBackoff = time.Millisecond
	defer func() { baseBackoff = old }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	d := newTestDispatcher()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})

	// One initial attempt plus maxSendRetries.
	if got := atomic.LoadInt32(&hits); got != int32(maxSendRetries+1) {
		t.Errorf("server was hit %d times, want %d", got, maxSendRetries+1)
	}
}

// After a successful send the destination is paced: nextSend is pushed into the
// future so the next delivery to the same URL waits.
func TestDeliverSetsNextSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := newTestDispatcher()
	before := time.Now()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})
	if !d.nextSend[srv.URL].After(before) {
		t.Error("nextSend was not advanced after a delivery, so pacing would not apply")
	}
}

// A full queue drops rather than blocking the event path.
func TestEnqueueDropsWhenFull(t *testing.T) {
	d := &Dispatcher{queue: make(chan queuedSend, 1)}
	d.enqueue("u", []byte("a"), "security") // fills the queue
	done := make(chan struct{})
	go func() {
		d.enqueue("u", []byte("b"), "security") // must not block
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enqueue blocked on a full queue instead of dropping")
	}
	if len(d.queue) != 1 {
		t.Errorf("queue length = %d, want 1 (second enqueue dropped)", len(d.queue))
	}
}

// 5xx is transient like 429, so it is retried and eventually succeeds.
func TestDeliverRetriesOn5xxThenSucceeds(t *testing.T) {
	old := baseBackoff
	baseBackoff = time.Millisecond
	defer func() { baseBackoff = old }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := newTestDispatcher()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("server hit %d times, want 2 (one 503 then success)", got)
	}
}

// A plain 4xx (e.g. a deleted webhook) is not retried.
func TestDeliverDoesNotRetry4xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound) // 404
	}))
	defer srv.Close()

	d := newTestDispatcher()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times, want 1 (404 not retried)", got)
	}
}

// A Retry-After longer than the cap makes deliver give up immediately rather
// than spinning through retries bound to fail.
func TestDeliverGivesUpWhenRetryAfterExceedsCap(t *testing.T) {
	oldMax := maxRetryWait
	maxRetryWait = 5 * time.Second
	defer func() { maxRetryWait = oldMax }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	d := newTestDispatcher()
	d.deliver(context.Background(), queuedSend{url: srv.URL, body: []byte("{}"), kind: "security"})
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times, want 1 (give up when Retry-After over cap)", got)
	}
}

// parseRetryAfter reports over-cap (and absurd/overflow) values as beyond the
// cap, so deliver gives up rather than overflowing.
func TestParseRetryAfterOverCap(t *testing.T) {
	oldMax := maxRetryWait
	maxRetryWait = 30 * time.Second
	defer func() { maxRetryWait = oldMax }()

	if d := parseRetryAfter("3600"); d <= maxRetryWait {
		t.Errorf("parseRetryAfter(3600) = %v, want > cap %v", d, maxRetryWait)
	}
	if d := parseRetryAfter("99999999999"); d <= maxRetryWait || d < 0 {
		t.Errorf("parseRetryAfter(huge) = %v, want a sane value over cap", d)
	}
}

// enqueue returning false must roll back the cooldown so the same event can be
// retried on its next occurrence rather than being suppressed after never being
// sent.
func TestEnqueueFailureRollsBackCooldown(t *testing.T) {
	d := &Dispatcher{
		last:  map[string]time.Time{},
		queue: make(chan queuedSend, 1),
	}
	d.queue <- queuedSend{url: "x"} // fill the queue so the next enqueue fails

	// Simulate what dispatch does: record cooldown, try to send, roll back on drop.
	key := "rule|fingerprint"
	d.last[key] = time.Now()
	if d.enqueue("x", []byte("{}"), "security") {
		t.Fatal("enqueue should have failed on a full queue")
	}
	d.rollbackCooldown(key)
	if _, exists := d.last[key]; exists {
		t.Error("cooldown was not rolled back after a dropped enqueue")
	}
}
