# EvergreenOS Device Agent

The EvergreenOS device agent is a long-running system daemon that onboards freshly
imaged EvergreenOS devices, keeps them compliant with administrator policy, and
continuously reports health back to Evergreen's control plane. It targets immutable
Fedora Silverblue derivatives and is designed to run unattended under systemd.

## Features

- **Hands-off enrollment** – collects immutable hardware facts, calls the backend
  `EnrollDevice` RPC, and persists the issued device token with `0600` permissions.
- **Signed policy enforcement** – periodically pulls versioned policy bundles,
  verifies signatures against a pinned Ed25519 public key, caches them locally,
  and reconciles Flatpak apps, Chromium policies (homepage, extensions, bookmarks,
  developer tools), rpm-ostree updates, NetworkManager Wi-Fi/VPN profiles, and
  SELinux/SSH/USBGuard controls.
- **State + telemetry** – gathers Flatpak inventory, rpm-ostree status, disk usage,
  and battery capacity before sending regular `ReportState` heartbeats. Snapshots
  are persisted to disk and retried when connectivity is restored.
- **Durable events** – records install/update/security results to a local JSON queue
  and flushes them to the backend with retry semantics.
- **Resilient execution loop** – gracefully handles missing host tooling, transient
  network failures, and persists its last-known-good policy and event queue.
- **TPM attestation** – periodically collects PCR quotes from the system TPM and
  submits them to the Evergreen backend when hardware support is present.

## Control-plane loops

```
┌──────────┐   enrolls & caches   ┌───────────┐
│ Enrollment│ ───────────────────▶ │ Credentials│
└────┬─────┘                      └────┬──────┘
     │                               │
     │ signed policy                 │ rotation
     ▼                               │
┌──────────┐    apply + events    ┌───▼──────────┐
│ Policy   │ ───────────────────▶ │ Enforcement │
└────┬─────┘                      └────┬────────┘
     │                               │
     │ telemetry & queue             │ attestation
     ▼                               ▼
┌──────────┐    buffered state    ┌────────────┐
│ State    │ ───────────────────▶ │ Event/State│
│ Collector│                      │ Queues      │
└──────────┘                      └────────────┘
```

## Repository layout

```
device-agent/
├── cmd/agent                # Main daemon entrypoint
├── internal/
│   ├── agent                # Top-level orchestration and scheduling loop
│   ├── apps                 # Flatpak reconciliation helpers
│   ├── browser              # Browser policy file writer
│   ├── config               # Runtime configuration loader/validator
│   ├── enroll               # Enrollment workflow and credential storage
│   ├── events               # Durable event queue helpers
│   ├── network              # NetworkManager keyfile writer
│   ├── policy               # Signature verification + policy fan-out
│   ├── security             # SELinux/SSH/USBGuard enforcement
│   ├── state                # State snapshot collector
│   ├── updates              # rpm-ostree integration
│   └── util                 # Logging, filesystem, and hardware utilities
├── pkg/api                  # REST client and policy/state/event DTOs
└── config/                  # Sample configuration and pinned policy key
```

## Building

The repository uses Go modules and only depends on the standard library. A normal
build of the daemon binary is therefore:

```bash
go build ./cmd/agent
```

> **Note:** In restricted environments without internet access, you may need to set
> `GOPROXY=off` and `GOSUMDB=off` when building. The source tree itself does not
> download external modules.

## Configuration

Runtime configuration is supplied via a JSON document (valid YAML subset) passed
with `--config`. The sample at [`config/agent.yaml`](config/agent.yaml) contains
all supported keys:

```json
{
  "backend_url": "https://selfhost-backend.example.com",
  "device_token_path": "/etc/evergreen/agent/secrets.json",
  "policy_cache_path": "/var/lib/evergreen/policy.json",
  "event_queue_path": "/var/lib/evergreen/events.json",
  "state_queue_path": "/var/lib/evergreen/state.json",
  "policy_public_key": "config/policy-public.pem",
  "enrollment": {
    "pre_shared_key": "",
    "config_path": ""
  },
  "intervals": {
    "policy_poll": "60s",
    "state_report": "5m",
    "event_flush": "30s",
    "retry_backoff": "15s",
    "retry_max_delay": "5m"
  },
  "logging": {
    "level": "info"
  }
}
```

Key fields:

- `backend_url` – Evergreen backend base URL (HTTPS required).
- `device_token_path` – location of the credential file written with `0600`
  permissions.
- `policy_public_key` – Ed25519 public key (PEM or raw bytes) used to validate
  policy signatures.
- `policy_cache_path` / `event_queue_path` / `state_queue_path` – persisted policy
  bundle, event log, and buffered state snapshots.
- `intervals` – control how often policy, state, and event loops run. Intervals
  accept Go duration strings (e.g. `"5m"`).

## Running the agent locally

```bash
go run ./cmd/agent --config config/agent.yaml
```

The agent performs the following lifecycle:

1. **Enrollment:** Collects hardware facts (serial, model, CPU, RAM, TPM presence),
   calls the backend, and stores the resulting device ID/token alongside the initial
   policy bundle.
2. **Policy loop:** On a schedule, posts the current policy version to
   `/api/v1/devices/policy`. Signed bundles are verified and then delegated to
   the respective managers (Flatpak, browser, rpm-ostree, NetworkManager,
   SELinux/SSH/USBGuard). All actions generate durable events.
3. **State loop:** Periodically gathers state (Flatpaks, rpm-ostree status, disk
   usage, battery level, last error) and writes snapshots to the durable state
   queue before sending `ReportState` payloads with retry semantics.
4. **Event loop:** Flushes queued events to `/api/v1/devices/events`, retrying
   until acknowledged.
5. **Attestation loop:** When TPM hardware is detected, collects PCR quotes and
   submits them to `/api/v1/devices/attest` for remote verification.

## Development workflow

- **Build:** `go build ./cmd/agent`
- **Test:** `go test ./...`
- **Run on a dev VM:**
  1. Copy `config/agent.yaml` to the VM and adjust URLs/paths.
  2. Place the pinned policy signing key referenced by `policy_public_key`.
  3. Execute `go run ./cmd/agent --config /path/to/agent.yaml` (requires network
     access to the Evergreen backend and rpm-ostree tooling on the host).

### Secrets & credential rotation

Device credentials (device ID/token) are written atomically with `0600`
permissions. When the backend rotates the device token (returned alongside policy
bundles), the agent automatically persists the new token together with the policy
version so restarts pick up the latest credentials.

All loops honour cancellation via `SIGINT`/`SIGTERM` and will record the last error
observed so it surfaces in subsequent state reports.

## Backend contract

The REST client in [`pkg/api`](pkg/api/client.go) targets the Evergreen backend
endpoints:

- `POST /api/v1/devices/enroll`
- `POST /api/v1/devices/policy`
- `POST /api/v1/devices/state`
- `POST /api/v1/devices/events`

The request/response structures mirror the product requirements document and can be
re-used for integration tests or mock servers.

## Security posture

- Device credentials are persisted using atomic writes and restrictive permissions.
- Policy enforcement only proceeds after Ed25519 signature verification succeeds.
- SELinux enforcing, SSH service state, and USBGuard service state are reconciled on
  every policy application.
- Browser defaults are materialised as JSON policy files that can be consumed by the
  Evergreen browser wrapper.

## Next steps

- Expand hardware inventory reporting (battery health, peripheral status).
- Add integration tests against a mocked rpm-ostree/systemd environment.
- Surface richer attestation failure diagnostics in the event stream.

