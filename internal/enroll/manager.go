package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/evergreen-os/device-agent/internal/config"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager handles device enrollment and credential persistence.
type Manager struct {
	cfg             config.Config
	client          *api.Client
	credentialsPath string
}

// Credentials describes the stored device identity.
type Credentials struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	Version     string `json:"policy_version"`
}

// NewManager constructs an enrollment manager.
func NewManager(cfg config.Config, client *api.Client) *Manager {
	return &Manager{
		cfg:             cfg,
		client:          client,
		credentialsPath: cfg.DeviceTokenPath,
	}
}

// EnsureEnrollment ensures the device is enrolled and credentials are persisted.
func (m *Manager) EnsureEnrollment(ctx context.Context) (Credentials, api.PolicyEnvelope, error) {
	cred, policy, err := m.loadCredentials()
	if err == nil && cred.DeviceToken != "" {
		return cred, policy, nil
	}
	configCred, configPolicy, cfgErr := m.loadEnrollmentConfig()
	if cfgErr == nil && configCred.DeviceToken != "" {
		if err := m.saveCredentials(configCred, configPolicy); err != nil {
			return Credentials{}, api.PolicyEnvelope{}, err
		}
		if err := m.clearEnrollmentConfig(); err != nil {
			return Credentials{}, api.PolicyEnvelope{}, err
		}
		return configCred, configPolicy, nil
	}
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		return Credentials{}, api.PolicyEnvelope{}, cfgErr
	}
	facts, err := util.CollectHardwareFacts()
	if err != nil {
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("collect hardware facts: %w", err)
	}
	req := api.EnrollDeviceRequest{
		SerialNumber: facts.SerialNumber,
		Model:        facts.Model,
		CPUModel:     facts.CPUModel,
		CPUCount:     facts.CPUCount,
		TotalRAM:     facts.TotalRAM,
		HasTPM:       facts.HasTPM,
		PreSharedKey: m.cfg.Enrollment.PreSharedKey,
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := m.client.EnrollDevice(ctx, req)
	if err != nil {
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("enroll device: %w", err)
	}
	cred = Credentials{
		DeviceID:    resp.DeviceID,
		DeviceToken: resp.DeviceToken,
		Version:     resp.Policy.Version,
	}
	if err := m.saveCredentials(cred, resp.Policy); err != nil {
		return Credentials{}, api.PolicyEnvelope{}, err
	}
	return cred, resp.Policy, nil
}

func (m *Manager) loadCredentials() (Credentials, api.PolicyEnvelope, error) {
	data, err := util.ReadSecretFile(m.credentialsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credentials{}, api.PolicyEnvelope{}, err
		}
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("read credentials: %w", err)
	}
	var stored struct {
		Cred   Credentials        `json:"credentials"`
		Policy api.PolicyEnvelope `json:"policy"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("decode credentials: %w", err)
	}
	return stored.Cred, stored.Policy, nil
}

func (m *Manager) saveCredentials(cred Credentials, policy api.PolicyEnvelope) error {
	payload := struct {
		Cred   Credentials        `json:"credentials"`
		Policy api.PolicyEnvelope `json:"policy"`
	}{Cred: cred, Policy: policy}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := util.WriteSecretFile(m.credentialsPath, data); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

func (m *Manager) loadEnrollmentConfig() (Credentials, api.PolicyEnvelope, error) {
	if m.cfg.Enrollment.ConfigPath == "" {
		return Credentials{}, api.PolicyEnvelope{}, os.ErrNotExist
	}
	data, err := os.ReadFile(m.cfg.Enrollment.ConfigPath)
	if err != nil {
		return Credentials{}, api.PolicyEnvelope{}, err
	}
	var payload struct {
		DeviceID    string             `json:"device_id"`
		DeviceToken string             `json:"device_token"`
		Policy      api.PolicyEnvelope `json:"policy"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("decode enrollment config: %w", err)
	}
	if payload.DeviceID == "" || payload.DeviceToken == "" {
		return Credentials{}, api.PolicyEnvelope{}, fmt.Errorf("enrollment config missing credentials")
	}
	cred := Credentials{
		DeviceID:    payload.DeviceID,
		DeviceToken: payload.DeviceToken,
		Version:     payload.Policy.Version,
	}
	return cred, payload.Policy, nil
}

func (m *Manager) clearEnrollmentConfig() error {
	if m.cfg.Enrollment.ConfigPath == "" {
		return nil
	}
	if err := os.Remove(m.cfg.Enrollment.ConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove enrollment config: %w", err)
	}
	return nil
}
