package auth

import (
	"sync"
	"time"
)

// LoginLimiter throttles login attempts per key (the client IP), so a password
// cannot be brute-forced by volume. Keyed on the source rather than the
// username on purpose: locking a username would let an attacker deny a real
// user by deliberately failing their login, whereas throttling the source only
// slows the attacker down.
//
// State is in memory, so it resets on restart. That is acceptable for
// brute-force defense: an attacker cannot force restarts, and bcrypt already
// makes each attempt cost ~50-100ms.
type LoginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptWindow
	max      int
	window   time.Duration
}

type attemptWindow struct {
	count int
	start time.Time
}

// NewLoginLimiter allows max failures per key within window before blocking for
// the rest of that window.
func NewLoginLimiter(max int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{
		attempts: make(map[string]*attemptWindow),
		max:      max,
		window:   window,
	}
}

// Attempt counts one login attempt and reports whether it may go ahead. The
// check and the count are one step, taken before the request body is read:
// counting only once a password had been checked let a client open many
// connections, pass the check on all of them, and then send every guess. A
// login that succeeds calls Reset, so only failures stay counted.
func (l *LoginLimiter) Attempt(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()
	w := l.attempts[key]
	if w == nil || time.Since(w.start) >= l.window {
		l.attempts[key] = &attemptWindow{count: 1, start: time.Now()}
		return true
	}
	if w.count >= l.max {
		return false
	}
	w.count++
	return true
}

// gcLocked drops elapsed windows once the map grows large, so a flood of
// distinct keys (e.g. spoofed sources) cannot grow it without bound. Cheap in
// the common case: it only scans past a generous threshold.
func (l *LoginLimiter) gcLocked() {
	if len(l.attempts) < 10000 {
		return
	}
	for k, w := range l.attempts {
		if time.Since(w.start) >= l.window {
			delete(l.attempts, k)
		}
	}
}

// Reset clears a key, called on a successful login so a legitimate user is not
// throttled by their own earlier typos.
func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
