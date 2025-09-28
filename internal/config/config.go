package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config models the agent configuration loaded from disk.
type Config struct {
	BackendURL      string     `json:"backend_url"`
	DeviceTokenPath string     `json:"device_token_path"`
	PolicyCachePath string     `json:"policy_cache_path"`
	EventQueuePath  string     `json:"event_queue_path"`
	PolicyPublicKey string     `json:"policy_public_key"`
	Enrollment      Enrollment `json:"enrollment"`
	Intervals       Intervals  `json:"intervals"`
	Logging         Logging    `json:"logging"`
}

// Enrollment specific settings.
type Enrollment struct {
	PreSharedKey string `json:"pre_shared_key"`
	ConfigPath   string `json:"config_path"`
}

// Intervals for background tasks.
type Intervals struct {
	PolicyPoll    Duration `json:"policy_poll"`
	StateReport   Duration `json:"state_report"`
	EventFlush    Duration `json:"event_flush"`
	RetryBackoff  Duration `json:"retry_backoff"`
	RetryMaxDelay Duration `json:"retry_max_delay"`
}

// Logging configuration.
type Logging struct {
	Level string `json:"level"`
}

// Duration wraps time.Duration to provide JSON unmarshalling from strings.
type Duration struct {
	time.Duration
}

// UnmarshalJSON parses a duration from string or number of seconds.
func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("duration: empty value")
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", s, err)
		}
		d.Duration = dur
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("parse duration seconds: %w", err)
	}
	d.Duration = time.Duration(seconds * float64(time.Second))
	return nil
}

// Load reads configuration from a file. The file must contain JSON or YAML (JSON subset).
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Validate ensures required fields are set.
func (c Config) Validate() error {
	if c.BackendURL == "" {
		return fmt.Errorf("backend_url is required")
	}
	if c.DeviceTokenPath == "" {
		return fmt.Errorf("device_token_path is required")
	}
	if c.PolicyCachePath == "" {
		return fmt.Errorf("policy_cache_path is required")
	}
	if c.EventQueuePath == "" {
		return fmt.Errorf("event_queue_path is required")
	}
	if c.PolicyPublicKey == "" {
		return fmt.Errorf("policy_public_key is required")
	}
	if c.Intervals.PolicyPoll.Duration == 0 {
		return fmt.Errorf("intervals.policy_poll must be >0")
	}
	if c.Intervals.StateReport.Duration == 0 {
		return fmt.Errorf("intervals.state_report must be >0")
	}
	if c.Intervals.EventFlush.Duration == 0 {
		return fmt.Errorf("intervals.event_flush must be >0")
	}
	return nil
}
