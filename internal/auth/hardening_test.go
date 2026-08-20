package auth

import (
	"testing"
	"time"
)

func TestPasswordMinimumLength(t *testing.T) {
	s := NewUserStore(t.TempDir() + "/users.json")
	if err := s.Create("bob", "short", RoleViewer); err != ErrPasswordTooShort {
		t.Errorf("Create with a 5-char password: err = %v, want ErrPasswordTooShort", err)
	}
	if err := s.Create("bob", "longenough", RoleViewer); err != nil {
		t.Errorf("Create with an 10-char password failed: %v", err)
	}
	if err := s.ChangePassword("bob", "tiny"); err != ErrPasswordTooShort {
		t.Errorf("ChangePassword too short: err = %v, want ErrPasswordTooShort", err)
	}
}

// The bootstrapped admin must change its password; changing it clears the gate.
func TestBootstrapAdminMustChangePassword(t *testing.T) {
	s := NewUserStore(t.TempDir() + "/users.json") // no file → bootstraps admin/admin
	if !s.RequiresPasswordChange("admin") {
		t.Fatal("bootstrapped admin is not flagged to change its password")
	}
	if err := s.ChangePassword("admin", "a-real-password"); err != nil {
		t.Fatal(err)
	}
	if s.RequiresPasswordChange("admin") {
		t.Error("the flag was not cleared after the password changed")
	}
}

func TestLoginLimiterBlocksAfterMax(t *testing.T) {
	l := NewLoginLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if l.Blocked("1.2.3.4") {
			t.Fatalf("blocked at attempt %d, before the limit", i)
		}
		l.Fail("1.2.3.4")
	}
	if !l.Blocked("1.2.3.4") {
		t.Error("not blocked after reaching the failure limit")
	}
	// Another source is unaffected — one attacker cannot lock out everyone.
	if l.Blocked("5.6.7.8") {
		t.Error("a different IP is blocked by another IP's failures")
	}
	// A success clears the block.
	l.Reset("1.2.3.4")
	if l.Blocked("1.2.3.4") {
		t.Error("still blocked after a reset")
	}
}

func TestLoginLimiterWindowExpires(t *testing.T) {
	l := NewLoginLimiter(1, 20*time.Millisecond)
	l.Fail("ip")
	if !l.Blocked("ip") {
		t.Fatal("not blocked immediately after the limit")
	}
	time.Sleep(30 * time.Millisecond)
	if l.Blocked("ip") {
		t.Error("still blocked after the window elapsed")
	}
}
