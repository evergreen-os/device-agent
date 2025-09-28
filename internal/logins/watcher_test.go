package logins

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClassifyMessageSuccess(t *testing.T) {
	msg := "pam_unix(gdm-password:session): session opened for user alice(uid=1000)"
	eventType, user, meta := classifyMessage(msg)
	if eventType != "login.success" {
		t.Fatalf("expected login.success, got %s", eventType)
	}
	if user != "alice" {
		t.Fatalf("expected user alice, got %s", user)
	}
	if meta != nil {
		t.Fatalf("expected nil metadata, got %#v", meta)
	}
}

func TestClassifyMessageFailure(t *testing.T) {
	msg := "pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=192.168.1.1 user=bob"
	eventType, user, meta := classifyMessage(msg)
	if eventType != "login.failure" {
		t.Fatalf("expected login.failure, got %s", eventType)
	}
	if user != "bob" {
		t.Fatalf("expected user bob, got %s", user)
	}
	if meta["reason"] != "bad_password" {
		t.Fatalf("expected bad_password reason, got %s", meta["reason"])
	}
	if meta["user"] != "" {
		t.Fatalf("unexpected user key in metadata: %#v", meta)
	}
}

func TestParseJournalEntry(t *testing.T) {
	payload := map[string]any{
		"__REALTIME_TIMESTAMP": "1700000000000000",
		"MESSAGE":              "pam_unix(gdm-password:session): session opened for user test(uid=1000)",
		"SYSLOG_IDENTIFIER":    "gdm-password",
		"_HOSTNAME":            "evergreen",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	entry, ok, err := parseJournalEntry(data)
	if err != nil {
		t.Fatalf("parseJournalEntry error: %v", err)
	}
	if !ok {
		t.Fatalf("expected entry to be parsed")
	}
	if entry.EventType != "login.success" {
		t.Fatalf("unexpected event type %s", entry.EventType)
	}
	if entry.User != "test" {
		t.Fatalf("unexpected user %s", entry.User)
	}
	expectedTime := time.UnixMicro(1700000000000000).UTC()
	if !entry.Timestamp.Equal(expectedTime) {
		t.Fatalf("expected timestamp %v, got %v", expectedTime, entry.Timestamp)
	}
	if entry.Metadata["host"] != "evergreen" {
		t.Fatalf("expected host metadata, got %#v", entry.Metadata)
	}
}
