package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"

	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestManagerApplyWritesProfiles(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr := NewManager(logger, dir)

	policy := api.NetworkPolicy{
		WiFi: []api.WiFiNetwork{{
			SSID:       "Example Corp",
			Passphrase: "secret",
			Security:   "wpa-psk",
		}},
		VPNs: []api.VPNProfile{{
			Name:        "Corp VPN",
			ServiceType: "org.freedesktop.NetworkManager.openvpn",
			Data: map[string]string{
				"remote": "vpn.example.com",
			},
			Secrets: map[string]string{
				"password": "hunter2",
			},
			AutoConnect: true,
		}},
		VPNDNS: []string{"1.1.1.1", "9.9.9.9"},
	}

	events, err := mgr.Apply(policy)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected events for wifi and vpn, got %d", len(events))
	}

	wifiPath := filepath.Join(dir, "Example_Corp.nmconnection")
	data, err := os.ReadFile(wifiPath)
	if err != nil {
		t.Fatalf("read wifi profile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "[wifi]") || !strings.Contains(content, "ssid=Example Corp") {
		t.Fatalf("wifi profile missing fields: %s", content)
	}

	vpnPath := filepath.Join(dir, "Corp_VPN.nmconnection")
	data, err = os.ReadFile(vpnPath)
	if err != nil {
		t.Fatalf("read vpn profile: %v", err)
	}
	vpnContent := string(data)
	if !strings.Contains(vpnContent, "[vpn]") || !strings.Contains(vpnContent, "remote=vpn.example.com") {
		t.Fatalf("vpn profile missing data: %s", vpnContent)
	}
	if !strings.Contains(vpnContent, "dns=1.1.1.1;9.9.9.9") {
		t.Fatalf("vpn dns not rendered: %s", vpnContent)
	}
}
