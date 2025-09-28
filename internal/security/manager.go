package security

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager enforces SELinux, SSH, and USBGuard policies.
type Manager struct {
	logger            *slog.Logger
	usbGuardRulesPath string
}

// Option configures the Manager.
type Option func(*Manager)

// WithUSBGuardRulesPath overrides the default USBGuard rules path.
func WithUSBGuardRulesPath(path string) Option {
	return func(m *Manager) {
		m.usbGuardRulesPath = path
	}
}

// NewManager constructs a new Manager.
func NewManager(logger *slog.Logger, opts ...Option) *Manager {
	m := &Manager{logger: logger, usbGuardRulesPath: "/etc/usbguard/rules.conf"}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Apply enforces security controls and emits events.
func (m *Manager) Apply(ctx context.Context, policy api.SecurityPolicy) ([]api.Event, error) {
	var eventsOut []api.Event
	if err := m.ensureSELinux(policy.SELinuxEnforce); err != nil {
		m.logger.Error("failed to configure selinux", slog.String("error", err.Error()))
		eventsOut = append(eventsOut, events.NewEvent("security.selinux.failure", map[string]string{"error": err.Error()}))
	} else {
		state := "permissive"
		if policy.SELinuxEnforce {
			state = "enforcing"
		}
		eventsOut = append(eventsOut, events.NewEvent("security.selinux.success", map[string]string{"state": state}))
	}
	if err := m.configureSSH(policy.AllowRootLogin); err != nil {
		m.logger.Error("failed to configure ssh", slog.String("error", err.Error()))
		eventsOut = append(eventsOut, events.NewEvent("security.ssh.config.failure", map[string]string{"error": err.Error()}))
	} else {
		mode := "disabled"
		if policy.AllowRootLogin {
			mode = "enabled"
		}
		eventsOut = append(eventsOut, events.NewEvent("security.ssh.config.success", map[string]string{"root_login": mode}))
	}
	if err := m.toggleService(ctx, "sshd", policy.SSHEnabled); err != nil {
		m.logger.Error("failed to toggle ssh", slog.String("error", err.Error()))
		eventsOut = append(eventsOut, events.NewEvent("security.ssh.failure", map[string]string{"error": err.Error()}))
	} else {
		state := "disabled"
		if policy.SSHEnabled {
			state = "enabled"
		}
		eventsOut = append(eventsOut, events.NewEvent("security.ssh.success", map[string]string{"state": state}))
	}
	if policy.USBGuard {
		if err := m.writeUSBGuardRules(policy.USBGuardRules); err != nil {
			m.logger.Error("failed to apply usbguard rules", slog.String("error", err.Error()))
			eventsOut = append(eventsOut, events.NewEvent("security.usbguard.failure", map[string]string{"error": err.Error()}))
		} else {
			eventsOut = append(eventsOut, events.NewEvent("security.usbguard.rules", map[string]string{"count": strconv.Itoa(len(policy.USBGuardRules))}))
		}
	} else {
		if err := m.removeUSBGuardRules(); err != nil {
			m.logger.Warn("failed to remove usbguard rules", slog.String("error", err.Error()))
		}
	}
	if err := m.toggleService(ctx, "usbguard", policy.USBGuard); err != nil {
		m.logger.Error("failed to toggle usbguard", slog.String("error", err.Error()))
		eventsOut = append(eventsOut, events.NewEvent("security.usbguard.failure", map[string]string{"error": err.Error()}))
	} else {
		state := "disabled"
		if policy.USBGuard {
			state = "enabled"
		}
		eventsOut = append(eventsOut, events.NewEvent("security.usbguard.success", map[string]string{"state": state}))
	}
	return eventsOut, nil
}

func (m *Manager) ensureSELinux(enforce bool) error {
	path := "/sys/fs/selinux/enforce"
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read selinux enforce: %w", err)
	}
	should := byte('0')
	if enforce {
		should = '1'
	}
	if len(current) > 0 && current[0] == should {
		return nil
	}
	if _, err := exec.LookPath("setenforce"); err != nil {
		return fmt.Errorf("setenforce not available: %w", err)
	}
	mode := "0"
	if enforce {
		mode = "1"
	}
	cmd := exec.Command("setenforce", mode)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setenforce %s: %w (%s)", mode, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *Manager) toggleService(ctx context.Context, service string, enable bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not available: %w", err)
	}
	args := []string{"disable", "--now", service}
	if enable {
		args = []string{"enable", "--now", service}
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s %s: %w (%s)", args[0], service, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *Manager) writeUSBGuardRules(rules []string) error {
	if err := util.EnsureParentDir(m.usbGuardRulesPath, 0o750); err != nil {
		return err
	}
	content := "# Managed by evergreen device agent\n"
	if len(rules) > 0 {
		content += strings.Join(rules, "\n") + "\n"
	}
	tmp := m.usbGuardRulesPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write usbguard rules: %w", err)
	}
	if err := os.Rename(tmp, m.usbGuardRulesPath); err != nil {
		return fmt.Errorf("commit usbguard rules: %w", err)
	}
	return nil
}

func (m *Manager) removeUSBGuardRules() error {
	if err := os.Remove(m.usbGuardRulesPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m *Manager) configureSSH(allowRoot bool) error {
	path := "/etc/ssh/sshd_config.d/evergreen.conf"
	if err := util.EnsureParentDir(path, 0o755); err != nil {
		return err
	}
	mode := "no"
	if allowRoot {
		mode = "yes"
	}
	content := fmt.Sprintf("# Managed by evergreen device agent\nPermitRootLogin %s\n", mode)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write ssh config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit ssh config: %w", err)
	}
	return nil
}
