package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/evergreen-os/device-agent/internal/config"
	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestEnsureEnrollmentUsesConfigFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "secrets.json")
	handoffPath := filepath.Join(dir, "handoff.json")

	cfg := config.Config{
		DeviceTokenPath: tokenPath,
		Enrollment: config.Enrollment{
			ConfigPath: handoffPath,
		},
	}
	manager := NewManager(cfg, nil)

	payload := struct {
		DeviceID    string             `json:"device_id"`
		DeviceToken string             `json:"device_token"`
		Policy      api.PolicyEnvelope `json:"policy"`
	}{
		DeviceID:    "device-123",
		DeviceToken: "token-abc",
		Policy: api.PolicyEnvelope{
			Version: "v1",
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := os.WriteFile(handoffPath, data, 0o600); err != nil {
		t.Fatalf("write handoff: %v", err)
	}

	cred, policy, err := manager.EnsureEnrollment(context.Background())
	if err != nil {
		t.Fatalf("EnsureEnrollment returned error: %v", err)
	}
	if cred.DeviceID != payload.DeviceID || cred.DeviceToken != payload.DeviceToken {
		t.Fatalf("unexpected credentials: %+v", cred)
	}
	if policy.Version != payload.Policy.Version {
		t.Fatalf("unexpected policy version: %s", policy.Version)
	}

	if _, err := os.Stat(handoffPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected handoff file removed, got error %v", err)
	}

	saved, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("expected credentials saved: %v", err)
	}
	var stored struct {
		Cred   Credentials        `json:"credentials"`
		Policy api.PolicyEnvelope `json:"policy"`
	}
	if err := json.Unmarshal(saved, &stored); err != nil {
		t.Fatalf("unmarshal saved credentials: %v", err)
	}
	if stored.Cred.DeviceID != payload.DeviceID || stored.Cred.DeviceToken != payload.DeviceToken {
		t.Fatalf("stored credentials mismatch: %+v", stored.Cred)
	}
}
