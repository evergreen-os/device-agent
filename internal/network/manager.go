package network

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager writes NetworkManager keyfiles according to policy.
type Manager struct {
	logger    *slog.Logger
	outputDir string
}

// NewManager creates a new network manager.
func NewManager(logger *slog.Logger, outputDir string) *Manager {
	if outputDir == "" {
		outputDir = "/etc/NetworkManager/system-connections"
	}
	return &Manager{logger: logger, outputDir: outputDir}
}

// Apply enforces Wi-Fi profiles.
func (m *Manager) Apply(policy api.NetworkPolicy) ([]api.Event, error) {
	if err := util.EnsureDir(m.outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("ensure network dir: %w", err)
	}
	var eventsOut []api.Event
	seen := map[string]struct{}{}
	for _, wifi := range policy.WiFi {
		file := filepath.Join(m.outputDir, sanitizeSSID(wifi.SSID)+".nmconnection")
		if err := os.WriteFile(file, []byte(renderKeyfile(wifi)), 0o600); err != nil {
			m.logger.Error("failed to write wifi profile", slog.String("ssid", wifi.SSID), slog.String("error", err.Error()))
			eventsOut = append(eventsOut, events.NewEvent("network.profile.failure", map[string]string{"ssid": wifi.SSID, "error": err.Error()}))
			continue
		}
		m.logger.Info("updated wifi profile", slog.String("ssid", wifi.SSID), slog.String("path", file))
		eventsOut = append(eventsOut, events.NewEvent("network.profile.success", map[string]string{"ssid": wifi.SSID}))
		seen[file] = struct{}{}
	}
	entries, err := os.ReadDir(m.outputDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			full := filepath.Join(m.outputDir, entry.Name())
			if !strings.HasSuffix(entry.Name(), ".nmconnection") {
				continue
			}
			if _, ok := seen[full]; !ok {
				if err := os.Remove(full); err != nil {
					m.logger.Warn("failed to remove stale wifi profile", slog.String("path", full), slog.String("error", err.Error()))
					continue
				}
				m.logger.Info("removed stale wifi profile", slog.String("path", full))
			}
		}
	}
	return eventsOut, nil
}

func sanitizeSSID(ssid string) string {
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_")
	return replacer.Replace(ssid)
}

func renderKeyfile(wifi api.WiFiNetwork) string {
	security := strings.ToUpper(wifi.Security)
	if security == "" {
		security = "wpa-psk"
	}
	builder := strings.Builder{}
	builder.WriteString("[connection]\n")
	builder.WriteString(fmt.Sprintf("id=%s\n", wifi.SSID))
	builder.WriteString("type=wifi\n")
	builder.WriteString("interface-name=\n")
	builder.WriteString("permissions=\n\n")
	builder.WriteString("[wifi]\n")
	builder.WriteString(fmt.Sprintf("ssid=%s\n", wifi.SSID))
	builder.WriteString("mode=infrastructure\n")
	builder.WriteString("hidden=false\n\n")
	builder.WriteString("[wifi-security]\n")
	builder.WriteString(fmt.Sprintf("key-mgmt=%s\n", strings.ToLower(security)))
	if wifi.Passphrase != "" {
		builder.WriteString(fmt.Sprintf("psk=%s\n", wifi.Passphrase))
	}
	builder.WriteString("\n[ipv4]\nmethod=auto\n\n")
	builder.WriteString("[ipv6]\nmethod=auto\n")
	return builder.String()
}
