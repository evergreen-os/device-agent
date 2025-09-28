package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/evergreen-os/device-agent/internal/apps"
	"github.com/evergreen-os/device-agent/internal/browser"
	"github.com/evergreen-os/device-agent/internal/config"
	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/internal/network"
	"github.com/evergreen-os/device-agent/internal/security"
	"github.com/evergreen-os/device-agent/internal/updates"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Manager coordinates policy verification, caching, and enforcement.
type Manager struct {
	logger   *slog.Logger
	cfg      config.Config
	verifier *Verifier
	cache    string

	apps     *apps.Manager
	browser  *browser.Manager
	updates  *updates.Manager
	network  *network.Manager
	security *security.Manager

	lastVersion string
}

// NewManager constructs a policy manager.
func NewManager(logger *slog.Logger, cfg config.Config, verifier *Verifier, apps *apps.Manager, browser *browser.Manager, updates *updates.Manager, network *network.Manager, security *security.Manager) *Manager {
	return &Manager{
		logger:   logger,
		cfg:      cfg,
		verifier: verifier,
		cache:    cfg.PolicyCachePath,
		apps:     apps,
		browser:  browser,
		updates:  updates,
		network:  network,
		security: security,
	}
}

// Apply verifies and enforces a policy bundle.
func (m *Manager) Apply(ctx context.Context, envelope api.PolicyEnvelope) ([]api.Event, error) {
	if m.verifier != nil {
		if err := m.verifier.Verify(envelope); err != nil {
			return nil, fmt.Errorf("verify policy: %w", err)
		}
	}
	if err := m.persist(envelope); err != nil {
		return nil, err
	}
	var generated []api.Event
	if events, err := m.apps.Apply(ctx, envelope.Policy.Apps); err != nil {
		m.logger.Error("app reconciliation failed", slog.String("error", err.Error()))
		generated = append(generated, events...)
		return generated, err
	} else {
		generated = append(generated, events...)
	}
	if events, err := m.browser.Apply(envelope.Policy.Browser); err != nil {
		m.logger.Error("browser enforcement failed", slog.String("error", err.Error()))
		generated = append(generated, events...)
		return generated, err
	} else {
		generated = append(generated, events...)
	}
	if result, err := m.updates.Apply(ctx, envelope.Policy.Updates); err != nil {
		m.logger.Error("update apply failed", slog.String("error", err.Error()))
		generated = append(generated, result.Events...)
		return generated, err
	} else {
		generated = append(generated, result.Events...)
	}
	if events, err := m.network.Apply(envelope.Policy.Network); err != nil {
		m.logger.Error("network enforcement failed", slog.String("error", err.Error()))
		generated = append(generated, events...)
		return generated, err
	} else {
		generated = append(generated, events...)
	}
	if events, err := m.security.Apply(ctx, envelope.Policy.Security); err != nil {
		m.logger.Error("security enforcement failed", slog.String("error", err.Error()))
		generated = append(generated, events...)
		return generated, err
	} else {
		generated = append(generated, events...)
	}
	m.lastVersion = envelope.Version
	generated = append(generated, events.NewEvent("policy.apply.success", map[string]string{"version": envelope.Version}))
	return generated, nil
}

// CachedPolicy returns the last persisted policy.
func (m *Manager) CachedPolicy() (api.PolicyEnvelope, error) {
	data, err := os.ReadFile(m.cache)
	if err != nil {
		return api.PolicyEnvelope{}, err
	}
	var env api.PolicyEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return api.PolicyEnvelope{}, fmt.Errorf("decode cached policy: %w", err)
	}
	return env, nil
}

func (m *Manager) persist(envelope api.PolicyEnvelope) error {
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	if err := util.EnsureParentDir(m.cache, 0o700); err != nil {
		return err
	}
	tmp := m.cache + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write policy cache: %w", err)
	}
	if err := os.Rename(tmp, m.cache); err != nil {
		return fmt.Errorf("rename policy cache: %w", err)
	}
	return nil
}

// LastVersion returns the last policy version applied.
func (m *Manager) LastVersion() string {
	return m.lastVersion
}
