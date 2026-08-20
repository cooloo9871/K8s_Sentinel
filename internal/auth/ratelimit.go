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

// Blocked reports whether the key has exhausted its allowance in the current
// window. A window that has elapsed is reset here, so the block lifts on its own.
func (l *LoginLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.attempts[key]
	if w == nil {
		return false
	}
	if time.Since(w.start) >= l.window {
		delete(l.attempts, key)
		return false
	}
	return w.count >= l.max
}

// Fail records one failed attempt.
func (l *LoginLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.attempts[key]
	if w == nil || time.Since(w.start) >= l.window {
		l.attempts[key] = &attemptWindow{count: 1, start: time.Now()}
		return
	}
	w.count++
}

// Reset clears a key, called on a successful login so a legitimate user is not
// throttled by their own earlier typos.
func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
