package attestation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	agentevents "github.com/evergreen-os/device-agent/internal/events"
	"github.com/evergreen-os/device-agent/pkg/api"
	"github.com/google/go-attestation/attest"
)

// Manager handles TPM attestation workflows.
type Manager struct {
	logger *slog.Logger

	mu          sync.Mutex
	lastDigest  string
	lastAttempt time.Time
	minInterval time.Duration
}

// NewManager constructs a manager with sensible defaults.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger, minInterval: time.Hour}
}

// Attest performs a TPM-backed attestation if hardware is present.
func (m *Manager) Attest(ctx context.Context, client *api.Client, token, deviceID string) ([]api.Event, error) {
	if !m.hasTPM() {
		return nil, nil
	}
	now := time.Now()
	if !m.ready(now) {
		return nil, nil
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		if errors.Is(err, attest.ErrTPMNotAvailable) {
			return nil, nil
		}
		return nil, fmt.Errorf("open tpm: %w", err)
	}
	defer tpm.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		event := agentevents.NewEvent("attestation.boot.failure", map[string]string{"error": err.Error()})
		return []api.Event{event}, fmt.Errorf("create ak: %w", err)
	}
	defer ak.Close(tpm)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	params := ak.AttestationParameters()
	att, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		return []api.Event{agentevents.NewEvent("attestation.boot.failure", map[string]string{"error": err.Error()})}, fmt.Errorf("attest platform: %w", err)
	}
	pcrs := make(map[string]string, len(att.PCRs))
	for _, p := range att.PCRs {
		pcrs[fmt.Sprintf("%d", p.Index)] = hex.EncodeToString(p.Digest)
	}
	digest := hashPCRs(pcrs)

	m.mu.Lock()
	if digest == m.lastDigest {
		m.lastAttempt = now
		m.mu.Unlock()
		return nil, nil
	}
	m.mu.Unlock()

	quotes := make([]api.AttestationQuote, 0, len(att.Quotes))
	for _, q := range att.Quotes {
		quotes = append(quotes, api.AttestationQuote{
			Version:   tpmVersionString(q.Version),
			Quote:     base64.StdEncoding.EncodeToString(q.Quote),
			Signature: base64.StdEncoding.EncodeToString(q.Signature),
		})
	}

	req := api.AttestBootRequest{
		DeviceID: deviceID,
		Evidence: api.AttestationEvidence{
			Nonce:    base64.StdEncoding.EncodeToString(nonce),
			AKPublic: base64.StdEncoding.EncodeToString(params.Public),
			Quotes:   quotes,
			PCRs:     pcrs,
		},
	}
	if err := client.AttestBoot(ctx, token, req); err != nil {
		event := agentevents.NewEvent("attestation.boot.failure", map[string]string{"error": err.Error()})
		return []api.Event{event}, err
	}

	m.mu.Lock()
	m.lastDigest = digest
	m.lastAttempt = now
	m.mu.Unlock()

	payload := map[string]string{
		"nonce":       req.Evidence.Nonce,
		"quote_count": fmt.Sprintf("%d", len(req.Evidence.Quotes)),
	}
	return []api.Event{agentevents.NewEvent("attestation.boot.success", payload)}, nil
}

func (m *Manager) ready(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastAttempt.IsZero() {
		return true
	}
	if m.minInterval <= 0 {
		m.minInterval = time.Hour
	}
	return now.Sub(m.lastAttempt) >= m.minInterval
}

func (m *Manager) hasTPM() bool {
	candidates := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func hashPCRs(pcrs map[string]string) string {
	if len(pcrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(pcrs))
	for k := range pcrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hasher := sha256.New()
	for _, k := range keys {
		hasher.Write([]byte(k))
		hasher.Write([]byte("="))
		hasher.Write([]byte(pcrs[k]))
		hasher.Write([]byte(";"))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func tpmVersionString(v attest.TPMVersion) string {
	switch v {
	case attest.TPMVersion12:
		return "1.2"
	case attest.TPMVersion20:
		return "2.0"
	case attest.TPMVersionAgnostic:
		return "agnostic"
	default:
		return fmt.Sprintf("%d", v)
	}
}
