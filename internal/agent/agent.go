package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/evergreen-os/device-agent/internal/apps"
	"github.com/evergreen-os/device-agent/internal/attestation"
	"github.com/evergreen-os/device-agent/internal/browser"
	"github.com/evergreen-os/device-agent/internal/config"
	"github.com/evergreen-os/device-agent/internal/enroll"
	"github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/internal/logins"
	"github.com/evergreen-os/device-agent/internal/network"
	"github.com/evergreen-os/device-agent/internal/policy"
	"github.com/evergreen-os/device-agent/internal/security"
	"github.com/evergreen-os/device-agent/internal/state"
	"github.com/evergreen-os/device-agent/internal/updates"
	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Agent runs the Evergreen device agent lifecycle.
type Agent struct {
	cfg    config.Config
	logger *slog.Logger
	client *api.Client

	enrollManager  *enroll.Manager
	policyManager  *policy.Manager
	stateCollector *state.Collector
	eventQueue     *events.Queue
	stateQueue     *state.Queue
	updatesManager *updates.Manager
	loginWatcher   *logins.Watcher
	attestManager  *attestation.Manager

	credentials enroll.Credentials

	policyInterval time.Duration
	stateInterval  time.Duration
	eventInterval  time.Duration
	loginInterval  time.Duration
	attestInterval time.Duration

	retryBackoff  time.Duration
	retryMaxDelay time.Duration
}

// New constructs a fully wired Agent.
func New(ctx context.Context, cfg config.Config) (*Agent, error) {
	logger := util.ConfigureLogger(cfg.Logging.Level)
	client, err := api.New(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("init api client: %w", err)
	}
	enrollManager := enroll.NewManager(cfg, client)
	appsManager := apps.NewManager(logger)
	browserManager := browser.NewManager(logger, "")
	updatesManager := updates.NewManager(logger)
	networkManager := network.NewManager(logger, "")
	securityManager := security.NewManager(logger)
	verifier, err := policy.NewVerifier(cfg.PolicyPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load policy key: %w", err)
	}
	policyManager := policy.NewManager(logger, cfg, verifier, appsManager, browserManager, updatesManager, networkManager, securityManager)
	collector := state.NewCollector(logger, appsManager, updatesManager)
	queue := events.NewQueue(cfg.EventQueuePath)
	stateQueue := state.NewQueue(cfg.StateQueuePath)
	loginWatcher := logins.NewWatcher(logger)
	attestManager := attestation.NewManager(logger)
	return &Agent{
		cfg:            cfg,
		logger:         logger,
		client:         client,
		enrollManager:  enrollManager,
		policyManager:  policyManager,
		stateCollector: collector,
		eventQueue:     queue,
		stateQueue:     stateQueue,
		updatesManager: updatesManager,
		loginWatcher:   loginWatcher,
		attestManager:  attestManager,
		policyInterval: cfg.Intervals.PolicyPoll.Duration,
		stateInterval:  cfg.Intervals.StateReport.Duration,
		eventInterval:  cfg.Intervals.EventFlush.Duration,
		loginInterval:  cfg.Intervals.EventFlush.Duration,
		attestInterval: cfg.Intervals.StateReport.Duration,
		retryBackoff:   cfg.Intervals.RetryBackoff.Duration,
		retryMaxDelay:  cfg.Intervals.RetryMaxDelay.Duration,
	}, nil
}

// Run executes the agent until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	cred, initialPolicy, err := a.enrollManager.EnsureEnrollment(ctx)
	if err != nil {
		return err
	}
	a.credentials = cred
	if initialPolicy.Version != "" {
		a.logger.Info("applying initial policy", slog.String("version", initialPolicy.Version))
		if events, err := a.policyManager.Apply(ctx, initialPolicy); err != nil {
			a.stateCollector.SetLastError(err)
			a.appendEvents(events)
			return fmt.Errorf("apply initial policy: %w", err)
		} else {
			a.appendEvents(events)
		}
	}
	if err := a.resumeQueuedEvents(); err != nil {
		a.logger.Warn("failed to load queued events", slog.String("error", err.Error()))
	}
	a.logger.Info("agent ready", slog.String("device_id", cred.DeviceID))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	loops := 5
	errCh := make(chan error, loops)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- a.policyLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- a.stateLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- a.eventLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- a.loginLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- a.attestationLoop(ctx)
	}()

	var runErr error
	for i := 0; i < loops; i++ {
		select {
		case <-ctx.Done():
			runErr = ctx.Err()
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				runErr = err
				cancel()
			}
		}
	}
	wg.Wait()
	return runErr
}

func (a *Agent) policyLoop(ctx context.Context) error {
	return a.backoffLoop(ctx, a.policyInterval, func(loopCtx context.Context) error {
		if err := a.pullAndApplyPolicy(loopCtx); err != nil {
			a.logger.Warn("policy sync failed", slog.String("error", err.Error()))
			a.stateCollector.SetLastError(err)
			return err
		}
		a.stateCollector.SetLastError(nil)
		return nil
	})
}

func (a *Agent) pullAndApplyPolicy(ctx context.Context) error {
	version := a.policyManager.LastVersion()
	if version == "" {
		if cached, err := a.policyManager.CachedPolicy(); err == nil {
			version = cached.Version
		}
	}
	ctx, cancel := context.WithTimeout(ctx, a.policyInterval)
	defer cancel()
	envelope, err := a.client.PullPolicy(ctx, a.credentials.DeviceToken, version)
	if err != nil {
		if errors.Is(err, api.ErrNotModified) {
			return nil
		}
		return err
	}
	a.logger.Info("applying policy", slog.String("version", envelope.Version))
	events, err := a.policyManager.Apply(ctx, envelope)
	a.appendEvents(events)
	if err != nil {
		return err
	}
	if envelope.DeviceToken != "" && envelope.DeviceToken != a.credentials.DeviceToken {
		a.logger.Info("rotating device token")
		a.credentials.DeviceToken = envelope.DeviceToken
	}
	a.credentials.Version = envelope.Version
	if err := a.enrollManager.Persist(a.credentials, envelope); err != nil {
		return fmt.Errorf("persist credentials: %w", err)
	}
	return nil
}

func (a *Agent) stateLoop(ctx context.Context) error {
	return a.backoffLoop(ctx, a.stateInterval, func(loopCtx context.Context) error {
		if events, err := a.updatesManager.EnsureRollback(loopCtx); err != nil {
			a.logger.Warn("rollback orchestration failed", slog.String("error", err.Error()))
			a.appendEvents(events)
			a.stateCollector.SetLastError(err)
			return err
		} else {
			a.appendEvents(events)
		}
		if err := a.reportState(loopCtx); err != nil {
			a.logger.Warn("state report failed", slog.String("error", err.Error()))
			a.stateCollector.SetLastError(err)
			return err
		}
		a.stateCollector.SetLastError(nil)
		return nil
	})
}

func (a *Agent) reportState(ctx context.Context) error {
	snapshot, err := a.stateCollector.Snapshot(ctx)
	if err != nil {
		return err
	}
	if a.stateQueue != nil {
		if err := a.stateQueue.Append(snapshot); err != nil {
			return fmt.Errorf("persist state snapshot: %w", err)
		}
		for {
			pending, err := a.stateQueue.Load()
			if err != nil {
				return err
			}
			if len(pending) == 0 {
				break
			}
			current := pending[0]
			req := api.ReportStateRequest{DeviceID: a.credentials.DeviceID, State: current}
			loopCtx, cancel := context.WithTimeout(ctx, a.stateInterval)
			err = a.client.ReportState(loopCtx, a.credentials.DeviceToken, req)
			cancel()
			if err != nil {
				return err
			}
			if err := a.stateQueue.Replace(pending[1:]); err != nil {
				return err
			}
		}
		return nil
	}
	req := api.ReportStateRequest{DeviceID: a.credentials.DeviceID, State: snapshot}
	loopCtx, cancel := context.WithTimeout(ctx, a.stateInterval)
	defer cancel()
	if err := a.client.ReportState(loopCtx, a.credentials.DeviceToken, req); err != nil {
		return err
	}
	return nil
}

func (a *Agent) eventLoop(ctx context.Context) error {
	return a.backoffLoop(ctx, a.eventInterval, func(loopCtx context.Context) error {
		if err := a.flushEvents(loopCtx); err != nil {
			a.logger.Warn("event flush failed", slog.String("error", err.Error()))
			return err
		}
		return nil
	})
}

func (a *Agent) loginLoop(ctx context.Context) error {
	return a.backoffLoop(ctx, a.loginInterval, func(loopCtx context.Context) error {
		events, err := a.loginWatcher.Collect(loopCtx)
		if err != nil {
			a.logger.Warn("login event collection failed", slog.String("error", err.Error()))
			return err
		}
		a.appendEvents(events)
		return nil
	})
}

func (a *Agent) attestationLoop(ctx context.Context) error {
	return a.backoffLoop(ctx, a.attestInterval, func(loopCtx context.Context) error {
		if a.attestManager == nil {
			return nil
		}
		events, err := a.attestManager.Attest(loopCtx, a.client, a.credentials.DeviceToken, a.credentials.DeviceID)
		if err != nil {
			a.logger.Warn("attestation failed", slog.String("error", err.Error()))
			a.appendEvents(events)
			return err
		}
		a.appendEvents(events)
		return nil
	})
}

func (a *Agent) appendEvents(events []api.Event) {
	if len(events) == 0 {
		return
	}
	if err := a.eventQueue.Append(events...); err != nil {
		a.logger.Warn("failed to persist events", slog.String("error", err.Error()))
	}
}

func (a *Agent) resumeQueuedEvents() error {
	_, err := a.eventQueue.Load()
	return err
}

func (a *Agent) flushEvents(ctx context.Context) error {
	pending, err := a.eventQueue.Load()
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	req := api.ReportEventsRequest{
		DeviceID: a.credentials.DeviceID,
		Events:   pending,
	}
	ctx, cancel := context.WithTimeout(ctx, a.eventInterval)
	defer cancel()
	if err := a.client.ReportEvents(ctx, a.credentials.DeviceToken, req); err != nil {
		return err
	}
	return a.eventQueue.Replace([]api.Event{})
}

func (a *Agent) backoffLoop(ctx context.Context, interval time.Duration, work func(context.Context) error) error {
	if interval <= 0 {
		interval = time.Second
	}
	baseBackoff := a.retryBackoff
	if baseBackoff <= 0 {
		baseBackoff = time.Second
	}
	maxDelay := a.retryMaxDelay
	if maxDelay <= 0 {
		maxDelay = baseBackoff * 16
	}
	var wait time.Duration
	delay := baseBackoff
	for {
		if wait > 0 {
			if err := a.wait(ctx, wait); err != nil {
				return err
			}
		}
		err := work(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			wait = delay
			if delay < maxDelay {
				delay *= 2
				if delay > maxDelay {
					delay = maxDelay
				}
			}
			continue
		}
		wait = interval
		delay = baseBackoff
	}
}

func (a *Agent) wait(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
