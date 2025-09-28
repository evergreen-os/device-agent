package logins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	agentevents "github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Watcher tails system journal entries and emits login events.
type Watcher struct {
	logger *slog.Logger

	mu        sync.Mutex
	lastEvent time.Time
}

// NewWatcher constructs a login watcher.
func NewWatcher(logger *slog.Logger) *Watcher {
	return &Watcher{logger: logger}
}

// Collect inspects journal entries since the previous poll and emits login events.
func (w *Watcher) Collect(ctx context.Context) ([]api.Event, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("journalctl not available: %w", err)
	}

	w.mu.Lock()
	since := w.lastEvent
	w.mu.Unlock()
	if since.IsZero() {
		since = time.Now().Add(-5 * time.Minute)
	}

	args := []string{"--since", since.Format(time.RFC3339), "--lines=500", "--output=json"}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)

	var events []api.Event
	latest := since
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		entry, ok, err := parseJournalEntry(line)
		if err != nil {
			w.logger.Debug("failed to parse journal entry", slog.String("error", err.Error()))
			continue
		}
		if !ok {
			continue
		}
		if entry.Timestamp.After(latest) {
			latest = entry.Timestamp
		}
		payload := map[string]string{
			"user":    entry.User,
			"service": entry.Service,
		}
		for k, v := range entry.Metadata {
			payload[k] = v
		}
		events = append(events, agentevents.NewEvent(entry.EventType, payload))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan journal: %w", err)
	}

	if latest.After(since) {
		w.mu.Lock()
		if latest.After(w.lastEvent) {
			w.lastEvent = latest
		}
		w.mu.Unlock()
	}
	return events, nil
}

type journalEvent struct {
	Timestamp time.Time
	EventType string
	User      string
	Service   string
	Metadata  map[string]string
}

func parseJournalEntry(line []byte) (journalEvent, bool, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return journalEvent{}, false, err
	}
	ts, err := parseTimestamp(raw["__REALTIME_TIMESTAMP"])
	if err != nil {
		return journalEvent{}, false, err
	}
	message, _ := raw["MESSAGE"].(string)
	if message == "" {
		return journalEvent{}, false, nil
	}
	eventType, user, meta := classifyMessage(message)
	if eventType == "" {
		return journalEvent{}, false, nil
	}
	service := firstString(raw, "SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "UNIT")
	if service == "" {
		service = "unknown"
	}
	if meta == nil {
		meta = map[string]string{}
	}
	if host := firstString(raw, "_HOSTNAME"); host != "" {
		meta["host"] = host
	}
	return journalEvent{
		Timestamp: ts,
		EventType: eventType,
		User:      user,
		Service:   service,
		Metadata:  meta,
	}, true, nil
}

func parseTimestamp(raw any) (time.Time, error) {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return time.Time{}, errors.New("timestamp empty")
		}
		micros, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, err
		}
		return time.UnixMicro(micros).UTC(), nil
	case float64:
		return time.UnixMicro(int64(v)).UTC(), nil
	default:
		return time.Time{}, errors.New("timestamp missing")
	}
}

var (
	successPattern = regexp.MustCompile(`session opened for user ([^\s(]+)`)
	failurePattern = regexp.MustCompile(`(?:authentication failure;[^\n]*user=([^\s]+)|Failed password for (?:invalid user )?([^\s]+))`)
)

func classifyMessage(message string) (eventType, user string, metadata map[string]string) {
	if match := successPattern.FindStringSubmatch(message); len(match) > 1 {
		return "login.success", sanitizeUser(match[1]), nil
	}
	if match := failurePattern.FindStringSubmatch(message); len(match) > 0 {
		user := firstNonEmpty(match[1:])
		metadata = map[string]string{"reason": failureReason(message)}
		if kv := extractKeyValuePairs(message); len(kv) > 0 {
			delete(kv, "user")
			for k, v := range kv {
				metadata[k] = v
			}
		}
		return "login.failure", sanitizeUser(user), metadata
	}
	return "", "", nil
}

func failureReason(message string) string {
	if strings.Contains(strings.ToLower(message), "invalid user") {
		return "invalid_user"
	}
	if strings.Contains(strings.ToLower(message), "password") {
		return "bad_password"
	}
	return "unknown"
}

func extractKeyValuePairs(message string) map[string]string {
	parts := strings.Split(message, " ")
	result := map[string]string{}
	for _, part := range parts {
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || kv[1] == "" {
			continue
		}
		key := strings.TrimSuffix(kv[0], ";")
		key = strings.TrimPrefix(key, ";")
		result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(kv[1]), ";")
	}
	return result
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return "unknown"
}

func sanitizeUser(user string) string {
	if user == "" {
		return "unknown"
	}
	return strings.TrimSpace(user)
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
