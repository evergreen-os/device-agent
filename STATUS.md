# EvergreenOS Device Agent – PRD Coverage

## Implemented
- Enrollment workflow that persists device credentials after invoking the backend. See `internal/enroll/manager.go` and `cmd/agent/main.go` for wiring.
- Policy reconciliation across apps, browser, updates, network, and security subsystems, triggered from `internal/agent/agent.go`.
- State collection that reports installed Flatpaks, disk usage, battery data, and last error through `internal/state/collector.go`.
- Durable event queue with persisted event emission during policy application and subsystem enforcement in `internal/events/queue.go` and related managers.
- Resilient background loops that apply exponential backoff between retries in `internal/agent/agent.go`.
- Login success and failure capture via the journal-backed watcher in `internal/logins/watcher.go` with events persisted through the shared queue.
- rpm-ostree rollback orchestration that detects unhealthy boots and raises recovery events from `internal/updates/manager.go`.
- TPM-backed attestation pipeline that collects quotes and forwards them to the backend from `internal/attestation/manager.go`.

## Gaps
- None at this time.
