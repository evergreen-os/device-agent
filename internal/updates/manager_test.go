package updates

import (
	"testing"
	"time"
)

func TestParseStatusRollbackDetection(t *testing.T) {
	payload := map[string]any{
		"reboot-required": false,
		"deployments": []any{
			map[string]any{
				"booted":   true,
				"checksum": "booted",
				"origin":   "evergreenos:stable",
				"metadata": map[string]any{"ostree.boot-success": false},
			},
			map[string]any{
				"checksum": "previous",
			},
		},
	}
	status := parseStatus(payload)
	if !status.NeedsRollback {
		t.Fatalf("expected rollback detection")
	}
	if status.RollbackTarget != "previous" {
		t.Fatalf("expected rollback target, got %s", status.RollbackTarget)
	}
	if status.BootedChecksum != "booted" {
		t.Fatalf("expected booted checksum, got %s", status.BootedChecksum)
	}
	if status.Channel != "evergreenos:stable" {
		t.Fatalf("expected channel, got %s", status.Channel)
	}
}

func TestDeploymentNeedsRollbackFalse(t *testing.T) {
	dep := map[string]any{
		"booted": true,
		"state":  "idle",
		"metadata": map[string]any{
			"ostree.boot-success": true,
		},
	}
	if deploymentNeedsRollback(dep) {
		t.Fatalf("expected healthy deployment")
	}
}

func TestMaintenanceWindowsDaily(t *testing.T) {
	segments, err := parseMaintenanceWindows([]string{"Mon-Fri 02:00-03:00"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(segments) != 5 {
		t.Fatalf("expected one segment per weekday, got %d", len(segments))
	}
	monday := time.Date(2024, time.January, 1, 2, 30, 0, 0, time.UTC) // Monday
	if !maintenanceAllowsNow(segments, monday) {
		t.Fatalf("expected monday 02:30 within window")
	}
	outside := time.Date(2024, time.January, 1, 4, 0, 0, 0, time.UTC)
	if maintenanceAllowsNow(segments, outside) {
		t.Fatalf("expected monday 04:00 outside window")
	}
}

func TestMaintenanceWindowOvernight(t *testing.T) {
	segments, err := parseMaintenanceWindows([]string{"Sun 23:00-01:00"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sunday := time.Date(2024, time.January, 7, 23, 30, 0, 0, time.UTC)
	if !maintenanceAllowsNow(segments, sunday) {
		t.Fatalf("expected sunday 23:30 within window")
	}
	monday := time.Date(2024, time.January, 8, 0, 30, 0, 0, time.UTC)
	if !maintenanceAllowsNow(segments, monday) {
		t.Fatalf("expected monday 00:30 within overnight window")
	}
	outside := time.Date(2024, time.January, 8, 2, 0, 0, 0, time.UTC)
	if maintenanceAllowsNow(segments, outside) {
		t.Fatalf("expected monday 02:00 outside window")
	}
}

func TestNextMaintenanceWindow(t *testing.T) {
	segments, err := parseMaintenanceWindows([]string{"02:00-03:00"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	now := time.Date(2024, time.January, 1, 1, 0, 0, 0, time.UTC)
	next, ok := nextMaintenanceWindow(segments, now)
	if !ok {
		t.Fatalf("expected next window time")
	}
	expected := time.Date(2024, time.January, 1, 2, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Fatalf("expected next window at %s, got %s", expected, next)
	}
	afterWindow := time.Date(2024, time.January, 1, 4, 0, 0, 0, time.UTC)
	next, ok = nextMaintenanceWindow(segments, afterWindow)
	if !ok {
		t.Fatalf("expected next day window")
	}
	expected = time.Date(2024, time.January, 2, 2, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Fatalf("expected wrap to next day %s, got %s", expected, next)
	}
}
