package apps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager reconciles Flatpak applications against policy.
type Manager struct {
	logger *slog.Logger
}

// NewManager constructs a new Manager.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger}
}

// ListInstalled returns installed Flatpak applications.
func (m *Manager) ListInstalled(ctx context.Context) ([]api.InstalledApp, error) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		return nil, fmt.Errorf("flatpak not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "flatpak", "list", "--app", "--columns=application,branch,commit")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("flatpak list: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var apps []api.InstalledApp
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			parts = strings.Fields(line)
		}
		if len(parts) >= 3 {
			apps = append(apps, api.InstalledApp{ID: parts[0], Branch: parts[1], Version: parts[2]})
		}
	}
	return apps, scanner.Err()
}

// Apply enforces the desired application list.
func (m *Manager) Apply(ctx context.Context, policy api.AppsPolicy) ([]api.Event, error) {
	installed, err := m.ListInstalled(ctx)
	if err != nil {
		return nil, err
	}
	desired := map[string]api.AppDefinition{}
	for _, app := range policy.Required {
		desired[app.ID] = app
	}
	installedSet := map[string]api.InstalledApp{}
	for _, app := range installed {
		installedSet[app.ID] = app
	}
	var generated []api.Event
	for id, def := range desired {
		if _, ok := installedSet[id]; ok {
			continue
		}
		if err := m.installFlatpak(ctx, def); err != nil {
			m.logger.Error("failed to install app", slog.String("app", id), slog.String("error", err.Error()))
			generated = append(generated, events.NewEvent("app.install.failure", map[string]string{"app": id, "error": err.Error()}))
			continue
		}
		generated = append(generated, events.NewEvent("app.install.success", map[string]string{"app": id}))
	}
	for id := range installedSet {
		if _, ok := desired[id]; !ok {
			if err := m.removeFlatpak(ctx, id); err != nil {
				m.logger.Error("failed to remove app", slog.String("app", id), slog.String("error", err.Error()))
				generated = append(generated, events.NewEvent("app.remove.failure", map[string]string{"app": id, "error": err.Error()}))
				continue
			}
			generated = append(generated, events.NewEvent("app.remove.success", map[string]string{"app": id}))
		}
	}
	return generated, nil
}

func (m *Manager) installFlatpak(ctx context.Context, def api.AppDefinition) error {
	if def.ID == "" {
		return errors.New("app id missing")
	}
	if _, err := exec.LookPath("flatpak"); err != nil {
		return fmt.Errorf("flatpak not available: %w", err)
	}
	args := []string{"install", "-y"}
	if def.Source != "" {
		args = append(args, def.Source)
	}
	args = append(args, def.ID)
	cmd := exec.CommandContext(ctx, "flatpak", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("flatpak install %s: %w (%s)", def.ID, err, string(output))
	}
	return nil
}

func (m *Manager) removeFlatpak(ctx context.Context, id string) error {
	if _, err := exec.LookPath("flatpak"); err != nil {
		return fmt.Errorf("flatpak not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "flatpak", "uninstall", "-y", id)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("flatpak uninstall %s: %w (%s)", id, err, string(output))
	}
	return nil
}
