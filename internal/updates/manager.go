package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager orchestrates rpm-ostree operations.
type Manager struct {
	logger *slog.Logger
	mu     sync.Mutex

	lastRollbackAttempt string

	now           func() time.Time
	rebootCommand []string
}

const (
	minutesPerDay  = 24 * 60
	minutesPerWeek = 7 * minutesPerDay
)

type maintenanceWindowSegment struct {
	start int
	end   int
}

// Result summarises enforcement actions.
type Result struct {
	Status         string
	RebootRequired bool
	Events         []api.Event
}

// NewManager constructs an update manager.
type Option func(*Manager)

// WithNowFunc overrides the time source, useful for tests.
func WithNowFunc(fn func() time.Time) Option {
	return func(m *Manager) {
		if fn != nil {
			m.now = fn
		}
	}
}

// WithRebootCommand overrides the command used to trigger reboots.
func WithRebootCommand(cmd ...string) Option {
	return func(m *Manager) {
		if len(cmd) > 0 {
			m.rebootCommand = append([]string{}, cmd...)
		}
	}
}

func NewManager(logger *slog.Logger, opts ...Option) *Manager {
	m := &Manager{
		logger:        logger,
		now:           time.Now,
		rebootCommand: []string{"systemctl", "reboot"},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Apply enforces the update policy.
func (m *Manager) Apply(ctx context.Context, policy api.UpdatePolicy) (Result, error) {
	status, _, err := m.fetchStatus(ctx)
	if err != nil {
		return Result{Status: "unavailable"}, err
	}
	result := Result{Status: status.State, RebootRequired: status.RebootRequired}
	windows, err := parseMaintenanceWindows(policy.Maintenance)
	if err != nil {
		result.Events = append(result.Events, events.NewEvent("update.reboot.failure", map[string]string{"error": err.Error()}))
		return result, err
	}
	if policy.Channel != "" && status.Channel != policy.Channel {
		if err := m.rebase(ctx, policy.Channel); err != nil {
			result.Events = append(result.Events, events.NewEvent("update.apply.failure", map[string]string{"channel": policy.Channel, "error": err.Error()}))
			return result, err
		}
		result.Events = append(result.Events, events.NewEvent("update.apply.success", map[string]string{"channel": policy.Channel}))
		fresh, _, ferr := m.fetchStatus(ctx)
		if ferr == nil {
			result.Status = fresh.State
			result.RebootRequired = fresh.RebootRequired
		}
	}
	if policy.RebootRequired && result.RebootRequired {
		now := m.now()
		if maintenanceAllowsNow(windows, now) {
			if err := m.triggerReboot(ctx); err != nil {
				result.Events = append(result.Events, events.NewEvent("update.reboot.failure", map[string]string{"error": err.Error()}))
				return result, err
			}
			result.Events = append(result.Events, events.NewEvent("update.reboot.triggered", map[string]string{"time": now.Format(time.RFC3339)}))
		} else {
			if next, ok := nextMaintenanceWindow(windows, now); ok {
				payload := map[string]string{"scheduled_for": next.Format(time.RFC3339)}
				result.Events = append(result.Events, events.NewEvent("update.reboot.deferred", payload))
			} else {
				result.Events = append(result.Events, events.NewEvent("update.reboot.deferred", map[string]string{"reason": "no_window"}))
			}
		}
	}
	return result, nil
}

// Status describes the rpm-ostree state.
type Status struct {
	Channel        string
	State          string
	RebootRequired bool
	NeedsRollback  bool
	RollbackTarget string
	BootedChecksum string
}

func (s Status) String() string {
	if s.Channel == "" {
		return s.State
	}
	return fmt.Sprintf("%s (%s)", s.State, s.Channel)
}

func (m *Manager) fetchStatus(ctx context.Context) (Status, map[string]any, error) {
	if _, err := exec.LookPath("rpm-ostree"); err != nil {
		return Status{State: "unavailable"}, nil, fmt.Errorf("rpm-ostree not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "rpm-ostree", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return Status{State: "error"}, nil, fmt.Errorf("rpm-ostree status: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		return Status{State: "error"}, nil, fmt.Errorf("parse rpm-ostree status: %w", err)
	}
	status := parseStatus(payload)
	return status, payload, nil
}

// Status reports the current rpm-ostree status without enforcement.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	status, _, err := m.fetchStatus(ctx)
	return status, err
}

func (m *Manager) rebase(ctx context.Context, channel string) error {
	if _, err := exec.LookPath("rpm-ostree"); err != nil {
		return fmt.Errorf("rpm-ostree not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "rpm-ostree", "rebase", channel)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rpm-ostree rebase %s: %w (%s)", channel, err, string(output))
	}
	return nil
}

func (m *Manager) triggerReboot(ctx context.Context) error {
	cmd := append([]string{}, m.rebootCommand...)
	if len(cmd) == 0 {
		return fmt.Errorf("no reboot command configured")
	}
	if _, err := exec.LookPath(cmd[0]); err != nil {
		return fmt.Errorf("reboot command not available: %w", err)
	}
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("reboot command failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func extractChannel(origin string) string {
	if origin == "" {
		return ""
	}
	parts := strings.Fields(origin)
	for _, p := range parts {
		if strings.Contains(p, ":") {
			return p
		}
	}
	return origin
}

func parseStatus(payload map[string]any) Status {
	status := Status{State: "idle"}
	if payload == nil {
		return status
	}
	if reboot, ok := payload["reboot-required"].(bool); ok {
		status.RebootRequired = reboot
		if reboot {
			status.State = "reboot_required"
		}
	}
	if deployments, ok := payload["deployments"].([]any); ok {
		for _, raw := range deployments {
			dep, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			booted, _ := dep["booted"].(bool)
			if origin := stringValue(dep, "origin"); origin != "" && status.Channel == "" {
				status.Channel = extractChannel(origin)
			}
			if checksum := stringValue(dep, "checksum"); checksum != "" {
				if booted {
					status.BootedChecksum = checksum
				} else if status.RollbackTarget == "" {
					status.RollbackTarget = checksum
				}
			}
			if staged, ok := dep["staged"].(bool); ok && staged {
				status.State = "staged"
			}
			if booted {
				if state := stringValue(dep, "state"); state != "" {
					status.State = strings.ToLower(state)
				}
				if deploymentNeedsRollback(dep) {
					status.NeedsRollback = true
				}
			}
		}
	}
	if trans, ok := payload["transaction"].(map[string]any); ok {
		if kind := stringValue(trans, "kind"); kind != "" {
			status.State = strings.ToLower(kind)
		}
		if state := stringValue(trans, "state"); strings.Contains(strings.ToLower(state), "fail") {
			status.NeedsRollback = true
		}
	}
	if status.NeedsRollback && status.RollbackTarget == "" {
		if deployments, ok := payload["deployments"].([]any); ok {
			for _, raw := range deployments {
				dep, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if booted, _ := dep["booted"].(bool); booted {
					continue
				}
				if checksum := stringValue(dep, "checksum"); checksum != "" && checksum != status.BootedChecksum {
					status.RollbackTarget = checksum
					break
				}
			}
		}
	}
	if status.State == "" {
		status.State = "idle"
	}
	return status
}

func deploymentNeedsRollback(dep map[string]any) bool {
	if val, ok := dep["unbootable"].(bool); ok && val {
		return true
	}
	if val, ok := dep["rollback"].(bool); ok && val {
		return true
	}
	if state := strings.ToLower(stringValue(dep, "state")); state != "" {
		if strings.Contains(state, "rollback") || strings.Contains(state, "error") {
			return true
		}
	}
	if health := strings.ToLower(stringValue(dep, "health")); health != "" && strings.Contains(health, "degraded") {
		return true
	}
	if meta, ok := dep["metadata"].(map[string]any); ok {
		if success, ok := meta["ostree.boot-success"].(bool); ok && !success {
			return true
		}
		if health := strings.ToLower(stringValue(meta, "health")); health != "" && strings.Contains(health, "degraded") {
			return true
		}
	}
	return false
}

func stringValue(m map[string]any, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return ""
}

func parseMaintenanceWindows(entries []string) ([]maintenanceWindowSegment, error) {
	var segments []maintenanceWindowSegment
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		parsed, err := parseMaintenanceWindow(trimmed)
		if err != nil {
			return nil, err
		}
		segments = append(segments, parsed...)
	}
	return segments, nil
}

func maintenanceAllowsNow(segments []maintenanceWindowSegment, now time.Time) bool {
	if len(segments) == 0 {
		return true
	}
	minute := minuteOfWeek(now)
	for _, seg := range segments {
		if minute >= seg.start && minute < seg.end {
			return true
		}
	}
	return false
}

func nextMaintenanceWindow(segments []maintenanceWindowSegment, now time.Time) (time.Time, bool) {
	if len(segments) == 0 {
		return time.Time{}, false
	}
	base := now.Truncate(time.Minute)
	minute := minuteOfWeek(base)
	bestDelta := minutesPerWeek * 2
	for _, seg := range segments {
		start := seg.start
		delta := 0
		if start > minute {
			delta = start - minute
		} else {
			delta = minutesPerWeek - minute + start
		}
		if delta == 0 {
			continue
		}
		if delta < bestDelta {
			bestDelta = delta
		}
	}
	if bestDelta == minutesPerWeek*2 {
		return time.Time{}, false
	}
	return base.Add(time.Duration(bestDelta) * time.Minute), true
}

func parseMaintenanceWindow(entry string) ([]maintenanceWindowSegment, error) {
	parts := strings.Fields(entry)
	if len(parts) == 0 {
		return nil, fmt.Errorf("maintenance window entry empty")
	}
	timePart := parts[len(parts)-1]
	start, end, err := parseTimeRange(timePart)
	if err != nil {
		return nil, fmt.Errorf("parse maintenance window %q: %w", entry, err)
	}
	var days []time.Weekday
	if len(parts) > 1 {
		dayExpr := strings.Join(parts[:len(parts)-1], " ")
		days, err = parseDays(dayExpr)
		if err != nil {
			return nil, fmt.Errorf("parse maintenance window %q: %w", entry, err)
		}
	}
	return buildSegments(days, start, end), nil
}

func parseTimeRange(value string) (time.Duration, time.Duration, error) {
	pieces := strings.Split(value, "-")
	if len(pieces) != 2 {
		return 0, 0, fmt.Errorf("invalid time range %q", value)
	}
	start, err := parseClock(pieces[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := parseClock(pieces[1])
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func parseClock(value string) (time.Duration, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time value %q", value)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, fmt.Errorf("invalid hour %q", parts[0])
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid minute %q", parts[1])
	}
	return time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute, nil
}

func parseDays(value string) ([]time.Weekday, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "*" {
		return nil, nil
	}
	trimmed = strings.ReplaceAll(trimmed, " ", ",")
	tokens := strings.Split(trimmed, ",")
	seen := make(map[time.Weekday]bool)
	var days []time.Weekday
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			bounds := strings.SplitN(token, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid day range %q", token)
			}
			start, err := parseWeekday(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parseWeekday(bounds[1])
			if err != nil {
				return nil, err
			}
			for i := 0; i < 7; i++ {
				day := (start + i) % 7
				wd := time.Weekday(day)
				if !seen[wd] {
					days = append(days, wd)
					seen[wd] = true
				}
				if day == end {
					break
				}
			}
			continue
		}
		day, err := parseWeekday(token)
		if err != nil {
			return nil, err
		}
		wd := time.Weekday(day)
		if !seen[wd] {
			days = append(days, wd)
			seen[wd] = true
		}
	}
	return days, nil
}

func parseWeekday(token string) (int, error) {
	day, ok := weekdayLookup[strings.ToLower(token)]
	if !ok {
		return 0, fmt.Errorf("invalid weekday %q", token)
	}
	return int(day), nil
}

func buildSegments(days []time.Weekday, start, end time.Duration) []maintenanceWindowSegment {
	minutesStart := int(start / time.Minute)
	minutesEnd := int(end / time.Minute)
	if len(days) == 0 {
		days = []time.Weekday{
			time.Sunday,
			time.Monday,
			time.Tuesday,
			time.Wednesday,
			time.Thursday,
			time.Friday,
			time.Saturday,
		}
	}
	var segments []maintenanceWindowSegment
	for _, day := range days {
		base := int(day) * minutesPerDay
		if minutesStart == minutesEnd {
			segments = append(segments, maintenanceWindowSegment{start: base, end: base + minutesPerDay})
			continue
		}
		if minutesEnd > minutesStart {
			segments = append(segments, maintenanceWindowSegment{start: base + minutesStart, end: base + minutesEnd})
			continue
		}
		segments = append(segments, maintenanceWindowSegment{start: base + minutesStart, end: base + minutesPerDay})
		nextDay := (int(day) + 1) % 7
		segments = append(segments, maintenanceWindowSegment{start: nextDay * minutesPerDay, end: nextDay*minutesPerDay + minutesEnd})
	}
	return segments
}

func minuteOfWeek(t time.Time) int {
	tt := t.Truncate(time.Minute)
	return int(tt.Weekday())*minutesPerDay + tt.Hour()*60 + tt.Minute()
}

var weekdayLookup = map[string]time.Weekday{
	"sun":       time.Sunday,
	"sunday":    time.Sunday,
	"mon":       time.Monday,
	"monday":    time.Monday,
	"tue":       time.Tuesday,
	"tues":      time.Tuesday,
	"tuesday":   time.Tuesday,
	"wed":       time.Wednesday,
	"weds":      time.Wednesday,
	"wednesday": time.Wednesday,
	"thu":       time.Thursday,
	"thur":      time.Thursday,
	"thurs":     time.Thursday,
	"thursday":  time.Thursday,
	"fri":       time.Friday,
	"friday":    time.Friday,
	"sat":       time.Saturday,
	"saturday":  time.Saturday,
}

// EnsureRollback triggers rpm-ostree rollback when the booted deployment is unhealthy.
func (m *Manager) EnsureRollback(ctx context.Context) ([]api.Event, error) {
	status, _, err := m.fetchStatus(ctx)
	if err != nil {
		return nil, err
	}
	needsRollback := status.NeedsRollback
	if !needsRollback {
		if pending, derr := m.rollbackRequested(ctx); derr != nil {
			m.logger.Warn("rollback target detection failed", slog.String("error", derr.Error()))
		} else if pending {
			needsRollback = true
		}
	}
	if !needsRollback {
		m.mu.Lock()
		m.lastRollbackAttempt = ""
		m.mu.Unlock()
		return nil, nil
	}
	identifier := status.BootedChecksum
	if identifier == "" {
		identifier = status.Channel
	}
	m.mu.Lock()
	if identifier != "" && identifier == m.lastRollbackAttempt {
		m.mu.Unlock()
		return nil, nil
	}
	m.lastRollbackAttempt = identifier
	m.mu.Unlock()

	if err := m.rollback(ctx); err != nil {
		event := events.NewEvent("update.rollback.failure", map[string]string{"error": err.Error()})
		return []api.Event{event}, err
	}
	payload := map[string]string{}
	if status.RollbackTarget != "" {
		payload["target"] = status.RollbackTarget
	}
	event := events.NewEvent("update.rollback.triggered", payload)
	return []api.Event{event}, nil
}

// WaitForStabilisation polls rpm-ostree until no transaction is active.
func (m *Manager) WaitForStabilisation(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, _, err := m.fetchStatus(ctx)
		if err != nil {
			return err
		}
		if status.State == "idle" || status.State == "reboot_required" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("updates did not stabilise before timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (m *Manager) rollback(ctx context.Context) error {
	if _, err := exec.LookPath("rpm-ostree"); err != nil {
		return fmt.Errorf("rpm-ostree not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "rpm-ostree", "rollback")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rpm-ostree rollback: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *Manager) rollbackRequested(ctx context.Context) (bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, nil
	}
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "rollback.target")
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 3 {
				return false, nil
			}
		}
		return false, fmt.Errorf("systemctl is-active rollback.target: %w", err)
	}
	return true, nil
}
