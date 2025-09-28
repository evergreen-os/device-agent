package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestQueueAppendAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	queue := NewQueue(path)

	first := api.DeviceState{Timestamp: time.Now().UTC(), UpdateStatus: "ok"}
	if err := queue.Append(first); err != nil {
		t.Fatalf("append first: %v", err)
	}
	second := api.DeviceState{Timestamp: time.Now().UTC().Add(time.Minute), UpdateStatus: "pending"}
	if err := queue.Append(second); err != nil {
		t.Fatalf("append second: %v", err)
	}

	loaded, err := queue.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 states, got %d", len(loaded))
	}
	if loaded[0].UpdateStatus != "ok" || loaded[1].UpdateStatus != "pending" {
		t.Fatalf("unexpected order: %#v", loaded)
	}

	if err := queue.Replace(loaded[1:]); err != nil {
		t.Fatalf("replace: %v", err)
	}
	remaining, err := queue.Load()
	if err != nil {
		t.Fatalf("load remaining: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 state, got %d", len(remaining))
	}
	if remaining[0].UpdateStatus != "pending" {
		t.Fatalf("unexpected state: %#v", remaining[0])
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("queue file missing: %v", err)
	}
}
