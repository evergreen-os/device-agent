package browser

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
		path = "/etc/chromium/policies/managed/evergreen.json"
	}
	return &Manager{logger: logger, path: path}
}

// Apply writes the desired browser configuration file.
func (m *Manager) Apply(policy api.BrowserPolicy) ([]api.Event, error) {
	config := buildChromiumPolicy(policy)
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

func buildChromiumPolicy(policy api.BrowserPolicy) map[string]any {
	cfg := map[string]any{}
	homepage := strings.TrimSpace(policy.Homepage)
	if homepage != "" {
		cfg["HomepageLocation"] = homepage
		cfg["HomepageIsNewTabPage"] = false
		cfg["RestoreOnStartup"] = 4
		cfg["RestoreOnStartupURLs"] = []string{homepage}
	}
	if len(policy.Extensions) > 0 {
		cfg["ExtensionInstallForcelist"] = policy.Extensions
	} else {
		cfg["ExtensionInstallForcelist"] = []string{}
	}
	if policy.AllowDevTools {
		cfg["DeveloperToolsAvailability"] = 1
	} else {
		cfg["DeveloperToolsAvailability"] = 2
	}
	if len(policy.ManagedBookmarks) > 0 {
		bookmarks := make([]map[string]any, 0, len(policy.ManagedBookmarks))
		for _, bm := range policy.ManagedBookmarks {
			if bm.Name == "" || bm.URL == "" {
				continue
			}
			bookmarks = append(bookmarks, map[string]any{
				"toplevel_name": "Managed",
				"name":          bm.Name,
				"url":           bm.URL,
			})
		}
		if len(bookmarks) > 0 {
			cfg["ManagedBookmarks"] = bookmarks
		}
	}
	return cfg
}
