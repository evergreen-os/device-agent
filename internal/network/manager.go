package network

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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
		file := filepath.Join(m.outputDir, sanitizeName(wifi.SSID)+".nmconnection")
		if err := os.WriteFile(file, []byte(renderWiFiKeyfile(wifi)), 0o600); err != nil {
			m.logger.Error("failed to write wifi profile", slog.String("ssid", wifi.SSID), slog.String("error", err.Error()))
			eventsOut = append(eventsOut, events.NewEvent("network.profile.failure", map[string]string{"ssid": wifi.SSID, "error": err.Error()}))
			continue
		}
		m.logger.Info("updated wifi profile", slog.String("ssid", wifi.SSID), slog.String("path", file))
		eventsOut = append(eventsOut, events.NewEvent("network.profile.success", map[string]string{"ssid": wifi.SSID}))
		seen[file] = struct{}{}
	}
	for _, vpn := range policy.VPNs {
		file := filepath.Join(m.outputDir, sanitizeName(vpn.Name)+".nmconnection")
		if err := os.WriteFile(file, []byte(renderVPNKeyfile(vpn, policy.VPNDNS)), 0o600); err != nil {
			m.logger.Error("failed to write vpn profile", slog.String("name", vpn.Name), slog.String("error", err.Error()))
			eventsOut = append(eventsOut, events.NewEvent("network.vpn.failure", map[string]string{"name": vpn.Name, "error": err.Error()}))
			continue
		}
		m.logger.Info("updated vpn profile", slog.String("name", vpn.Name), slog.String("path", file))
		eventsOut = append(eventsOut, events.NewEvent("network.vpn.success", map[string]string{"name": vpn.Name}))
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
				m.logger.Info("removed stale network profile", slog.String("path", full))
			}
		}
	}
	return eventsOut, nil
}

func sanitizeName(name string) string {
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", "=", "_")
	return replacer.Replace(name)
}

func renderWiFiKeyfile(wifi api.WiFiNetwork) string {
	security := strings.ToUpper(wifi.Security)
	if security == "" {
		security = "wpa-psk"
	}
	builder := strings.Builder{}
	builder.WriteString("[connection]\n")
	builder.WriteString(fmt.Sprintf("id=%s\n", wifi.SSID))
	builder.WriteString("type=wifi\n")
	builder.WriteString("interface-name=\n")
	builder.WriteString("permissions=\n")
	if wifi.Metered {
		builder.WriteString("metered=2\n")
	}
	if wifi.Hidden {
		builder.WriteString("autoconnect=false\n")
	}
	builder.WriteString("\n")
	builder.WriteString("[wifi]\n")
	builder.WriteString(fmt.Sprintf("ssid=%s\n", wifi.SSID))
	builder.WriteString("mode=infrastructure\n")
	builder.WriteString(fmt.Sprintf("hidden=%t\n\n", wifi.Hidden))
	builder.WriteString("[wifi-security]\n")
	builder.WriteString(fmt.Sprintf("key-mgmt=%s\n", strings.ToLower(security)))
	if strings.EqualFold(security, "WPA-EAP") || strings.Contains(strings.ToLower(security), "eap") {
		builder.WriteString("auth-alg=open\n")
		for key, value := range wifi.EAP {
			if strings.HasPrefix(strings.ToLower(key), "password") {
				continue
			}
			builder.WriteString(fmt.Sprintf("%s=%s\n", strings.ToLower(key), value))
		}
	} else if wifi.Passphrase != "" {
		builder.WriteString(fmt.Sprintf("psk=%s\n", wifi.Passphrase))
	}
	if len(wifi.EAP) > 0 {
		builder.WriteString("\n[802-1x]\n")
		for key, value := range wifi.EAP {
			builder.WriteString(fmt.Sprintf("%s=%s\n", strings.ToLower(key), value))
		}
	}
	builder.WriteString("\n[ipv4]\nmethod=auto\n\n")
	builder.WriteString("[ipv6]\nmethod=auto\n")
	return builder.String()
}

func renderVPNKeyfile(vpn api.VPNProfile, dns []string) string {
	serviceType := vpn.ServiceType
	if serviceType == "" {
		serviceType = "org.freedesktop.NetworkManager.openvpn"
	}
	builder := strings.Builder{}
	builder.WriteString("[connection]\n")
	builder.WriteString(fmt.Sprintf("id=%s\n", vpn.Name))
	builder.WriteString("type=vpn\n")
	builder.WriteString("interface-name=\n")
	builder.WriteString("permissions=\n")
	if vpn.AutoConnect {
		builder.WriteString("autoconnect=true\n")
	}
	builder.WriteString("\n")
	builder.WriteString("[vpn]\n")
	builder.WriteString(fmt.Sprintf("service-type=%s\n", serviceType))
	keys := make([]string, 0, len(vpn.Data))
	for key := range vpn.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		builder.WriteString(fmt.Sprintf("%s=%s\n", key, vpn.Data[key]))
	}
	if len(vpn.Secrets) > 0 {
		builder.WriteString("\n[vpn-secrets]\n")
		secretKeys := make([]string, 0, len(vpn.Secrets))
		for key := range vpn.Secrets {
			secretKeys = append(secretKeys, key)
		}
		sort.Strings(secretKeys)
		for _, key := range secretKeys {
			builder.WriteString(fmt.Sprintf("%s=%s\n", key, vpn.Secrets[key]))
		}
	}
	builder.WriteString("\n[ipv4]\nmethod=auto\n")
	if len(dns) > 0 {
		builder.WriteString(fmt.Sprintf("dns=%s\n", strings.Join(dns, ";")))
		builder.WriteString("ignore-auto-dns=true\n")
	}
	builder.WriteString("\n[ipv6]\nmethod=auto\n")
	if len(dns) > 0 {
		builder.WriteString(fmt.Sprintf("dns=%s\n", strings.Join(dns, ";")))
		builder.WriteString("ignore-auto-dns=true\n")
	}
	return builder.String()
}
