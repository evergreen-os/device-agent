package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"
)

func TestWriteUSBGuardRules(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "usbguard", "rules.conf")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	m := NewManager(logger, WithUSBGuardRulesPath(rulesPath))

	rules := []string{"allow id 1", "block id 2"}
	if err := m.writeUSBGuardRules(rules); err != nil {
		t.Fatalf("writeUSBGuardRules returned error: %v", err)
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("expected rules file to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "allow id 1") || !strings.Contains(content, "block id 2") {
		t.Fatalf("rules file missing entries: %q", content)
	}
	if !strings.HasPrefix(content, "# Managed by evergreen device agent\n") {
		t.Fatalf("missing managed comment: %q", content)
	}

	info, err := os.Stat(rulesPath)
	if err != nil {
		t.Fatalf("stat rules file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected permissions 0600, got %v", info.Mode().Perm())
	}
}
