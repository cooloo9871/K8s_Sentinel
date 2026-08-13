package security

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
)

func denial(dest, srcPort string) k8s.TetragonEvent {
	return k8s.TetragonEvent{
		Type: "kprobe", PolicyName: "deny-egress", Function: "cilium-egress-deny",
		Action: "deny", Namespace: "demo", Pod: "client",
		NetDest: dest, NetSrc: "10.0.1.5:" + srcPort,
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "events.json"))
	t.Cleanup(s.WaitForFlush)
	return s
}

// drain collects what arrived without blocking on an empty channel.
func drain(ch <-chan k8s.TetragonEvent) []k8s.TetragonEvent {
	var out []k8s.TetragonEvent
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		case <-time.After(50 * time.Millisecond):
			return out
		}
	}
}

// Alerting and syslog used to read the raw event stream while the console
// folded repeats into one row, so a pod retrying a denied connection produced
// one row and a notification per attempt. The store is now the single arbiter:
// a repeat updates the row and notifies nobody.
func TestRepeatsNotifyOnce(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	for i := 0; i < 5; i++ {
		s.Add(denial("10.0.0.9:443", "40001"))
	}

	got := drain(ch)
	if len(got) != 1 {
		t.Errorf("got %d notifications for 5 repeats, want 1", len(got))
	}
	if rows := len(s.List()); rows != 1 {
		t.Errorf("got %d rows, want 1 — notifications and rows must agree", rows)
	}
	if c := s.List()[0].Count; c != 5 {
		t.Errorf("row count = %d, want 5 — the repeats still have to be counted", c)
	}
}

// The client-side port changes on every connection. Treating it as part of the
// identity would make every retry a new event, which is the noise the folding
// exists to remove.
func TestAChangingSourcePortIsStillTheSameEvent(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	s.Add(denial("10.0.0.9:443", "40001"))
	s.Add(denial("10.0.0.9:443", "51234"))

	if got := drain(ch); len(got) != 1 {
		t.Errorf("got %d notifications, want 1 — only the ephemeral port differed", len(got))
	}
}

// The other direction, and the reason the alert cooldown key had to change: two
// denials to different destinations are two events, and both must be reported.
func TestDifferentDestinationsAreDifferentEvents(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	s.Add(denial("10.0.0.9:443", "40001"))
	s.Add(denial("10.0.0.20:443", "40002"))

	got := drain(ch)
	if len(got) != 2 {
		t.Fatalf("got %d notifications, want 2 — these are different denials", len(got))
	}
	if len(s.List()) != 2 {
		t.Error("the events list disagrees with what was notified")
	}
}

// Fingerprint is what alerting keys its cooldown on, so the two directions above
// have to hold for it directly.
func TestFingerprintSeparatesWhatMatters(t *testing.T) {
	same := Fingerprint(denial("10.0.0.9:443", "40001")) == Fingerprint(denial("10.0.0.9:443", "59999"))
	if !same {
		t.Error("an ephemeral source port changed the fingerprint")
	}
	diff := Fingerprint(denial("10.0.0.9:443", "40001")) != Fingerprint(denial("10.0.0.20:443", "40001"))
	if !diff {
		t.Error("two destinations share a fingerprint, so one alert would swallow the other")
	}
}

// Events the store does not record must not notify either — otherwise the two
// disagree again, in the other direction.
func TestAnEventTheStoreRejectsNotifiesNobody(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	// No policy name: process-discovery traffic, not a security event.
	s.Add(k8s.TetragonEvent{Type: "kprobe", Namespace: "demo", Pod: "client",
		Time: time.Now().UTC().Format(time.RFC3339Nano)})

	if got := drain(ch); len(got) != 0 {
		t.Errorf("got %d notifications for an event that was never recorded", len(got))
	}
}

// A slow repeat falls outside the 30s folding window, so it opens a new row —
// and therefore notifies. This is the case the alert cooldown still exists for.
func TestARepeatBeyondTheWindowIsANewEvent(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	old := denial("10.0.0.9:443", "40001")
	old.Time = time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	s.Add(old)
	s.Add(denial("10.0.0.9:443", "40002"))

	if got := drain(ch); len(got) != 2 {
		t.Errorf("got %d notifications, want 2 — the repeat was outside the fold window", len(got))
	}
}

// The store rejecting an event and the notification feed announcing it is the
// exact divergence this feed exists to remove, so the drops have to be silent
// too. A retention cap of zero for a severity throws every one of them away.
func TestAnEventTheCapRejectsNotifiesNobody(t *testing.T) {
	s := newTestStore(t)
	s.SetRetention(RetentionConfig{MaxWarnings: 0, MaxCriticals: 300, TTLDays: 7})
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	// Action "monitor" makes this a warning, and warnings have no slots.
	s.Add(k8s.TetragonEvent{
		Type: "kprobe", PolicyName: "watch", Function: "sys_execve", Action: "monitor",
		Namespace: "demo", Pod: "client", Binary: "/bin/sh",
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})

	if rows := len(s.List()); rows != 0 {
		t.Fatalf("got %d rows, want the cap to have rejected it", rows)
	}
	if got := drain(ch); len(got) != 0 {
		t.Errorf("got %d notifications for an event the store threw away", len(got))
	}
}

// A timestamp the store cannot parse used to be kept verbatim on the row: the
// TTL filter then dropped the event while the feed still announced it, and the
// dedup window could never match the row again.
func TestAnUnreadableTimestampIsStampedNotDropped(t *testing.T) {
	s := newTestStore(t)
	ch, unsub := s.SubscribeFirstSightings()
	defer unsub()

	for i := 0; i < 3; i++ {
		s.Add(k8s.TetragonEvent{
			Type: "kprobe", PolicyName: "watch", Function: "sys_execve", Action: "monitor",
			Namespace: "demo", Pod: "client", Binary: "/bin/sh",
			Time: "not a timestamp",
		})
	}

	rows := s.List()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want one — the repeats must still fold together", len(rows))
	}
	if rows[0].Count != 3 {
		t.Errorf("count = %d, want 3", rows[0].Count)
	}
	if got := drain(ch); len(got) != 1 {
		t.Errorf("got %d notifications, want 1", len(got))
	}
}
