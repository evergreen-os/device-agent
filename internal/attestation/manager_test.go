package attestation

import (
	"testing"
	"time"
)

func TestHashPCRsDeterministic(t *testing.T) {
	pcrs := map[string]string{"0": "aaa", "7": "bbb", "1": "ccc"}
	first := hashPCRs(pcrs)
	second := hashPCRs(map[string]string{"7": "bbb", "1": "ccc", "0": "aaa"})
	if first == "" {
		t.Fatalf("expected hash value")
	}
	if first != second {
		t.Fatalf("expected deterministic hash, got %s and %s", first, second)
	}
}

func TestReadyInterval(t *testing.T) {
	mgr := NewManager(nil)
	now := time.Now()
	if !mgr.ready(now) {
		t.Fatalf("expected first call ready")
	}
	mgr.mu.Lock()
	mgr.lastAttempt = now
	mgr.mu.Unlock()
	if mgr.ready(now.Add(10 * time.Minute)) {
		t.Fatalf("expected interval gating")
	}
	if !mgr.ready(now.Add(time.Hour)) {
		t.Fatalf("expected ready after interval")
	}
}
