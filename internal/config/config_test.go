package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurationUnmarshalString(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"150s"`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Duration != 150*time.Second {
		t.Fatalf("expected 150s got %v", d.Duration)
	}
}

func TestDurationUnmarshalSeconds(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte("1.5")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Duration != 1500*time.Millisecond {
		t.Fatalf("expected 1.5s got %v", d.Duration)
	}
}

func TestLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	payload := []byte(`{
                "backend_url": "https://example.com",
                "device_token_path": "/etc/evergreen/token",
                "policy_cache_path": "/var/lib/evergreen/policy.json",
                "event_queue_path": "/var/lib/evergreen/events.json",
                "state_queue_path": "/var/lib/evergreen/state.json",
                "policy_public_key": "/etc/evergreen/policy.pem",
                "enrollment": {
                        "pre_shared_key": "secret",
                        "config_path": "/etc/evergreen/enroll.json"
                },
                "intervals": {
                        "policy_poll": "30s",
                        "state_report": "1m",
                        "event_flush": "15s",
                        "retry_backoff": "5s",
                        "retry_max_delay": "5m"
                },
                "logging": {
                        "level": "debug"
                }
        }`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if cfg.Intervals.PolicyPoll.Duration != 30*time.Second {
		t.Fatalf("unexpected policy interval %v", cfg.Intervals.PolicyPoll.Duration)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("unexpected logging level %q", cfg.Logging.Level)
	}
}

func TestValidateRequiresFields(t *testing.T) {
	cfg := Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty config")
	}
}
