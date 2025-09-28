package state

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/evergreen-os/device-agent/internal/updates"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// AppLister abstracts Flatpak inventory queries.
type AppLister interface {
	ListInstalled(ctx context.Context) ([]api.InstalledApp, error)
}

// UpdateStatusProvider abstracts rpm-ostree status queries.
type UpdateStatusProvider interface {
	Status(ctx context.Context) (updates.Status, error)
}

// Collector gathers device state for reporting.
type Collector struct {
	logger  *slog.Logger
	apps    AppLister
	updates UpdateStatusProvider
	lastErr string
}

// NewCollector constructs a collector.
func NewCollector(logger *slog.Logger, apps AppLister, updates UpdateStatusProvider) *Collector {
	return &Collector{logger: logger, apps: apps, updates: updates}
}

// SetLastError records the last operational error for reporting.
func (c *Collector) SetLastError(err error) {
	if err == nil {
		c.lastErr = ""
		return
	}
	c.lastErr = err.Error()
}

// Snapshot collects current device state.
func (c *Collector) Snapshot(ctx context.Context) (api.DeviceState, error) {
	installed, err := c.apps.ListInstalled(ctx)
	if err != nil {
		c.logger.Warn("failed to list apps", slog.String("error", err.Error()))
	}
	state := api.DeviceState{
		Timestamp:     time.Now().UTC(),
		InstalledApps: installed,
		LastError:     c.lastErr,
	}
	total, free, err := util.DiskUsage("/")
	if err != nil {
		c.logger.Warn("disk usage lookup failed", slog.String("error", err.Error()))
	} else {
		state.DiskTotalBytes = total
		state.DiskFreeBytes = free
	}
	if c.updates != nil {
		if status, err := c.updates.Status(ctx); err == nil {
			state.UpdateStatus = status.State
			if status.RebootRequired {
				state.UpdateStatus = "reboot_required"
			}
		} else {
			c.logger.Warn("update status failed", slog.String("error", err.Error()))
		}
	}
	if pct, err := batteryPercent(); err == nil {
		state.BatteryPercent = pct
	}
	return state, nil
}

func batteryPercent() (float64, error) {
	paths := []string{
		"/sys/class/power_supply/BAT0/capacity",
		"/sys/class/power_supply/BAT1/capacity",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(data))
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, fmt.Errorf("parse battery percent: %w", err)
		}
		return value, nil
	}
	return 0, fmt.Errorf("battery not present")
}
