package browser

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager enforces browser-related policy knobs.
type Manager struct {
	logger *slog.Logger
	path   string
}

// NewManager creates a browser manager writing to the provided path.
func NewManager(logger *slog.Logger, path string) *Manager {
	if path == "" {
		path = "/etc/evergreen/browser-policy.json"
	}
	return &Manager{logger: logger, path: path}
}

// Apply writes the desired browser configuration file.
func (m *Manager) Apply(policy api.BrowserPolicy) ([]api.Event, error) {
	config := map[string]any{
		"homepage":        policy.Homepage,
		"extensions":      policy.Extensions,
		"allow_dev_tools": policy.AllowDevTools,
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal browser policy: %w", err)
	}
	if err := util.EnsureParentDir(m.path, 0o700); err != nil {
		return nil, err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return nil, fmt.Errorf("write browser policy: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return nil, fmt.Errorf("rename browser policy: %w", err)
	}
	event := events.NewEvent("browser.policy.updated", map[string]string{"path": filepath.Clean(m.path)})
	return []api.Event{event}, nil
}
