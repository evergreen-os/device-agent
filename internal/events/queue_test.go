package events

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestQueueAppendLoadAndReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queue.json")
	queue := NewQueue(path)

	event := api.Event{ID: "1", Type: "test", Timestamp: time.Unix(1700000000, 0), Payload: map[string]string{"k": "v"}}
	if err := queue.Append(event); err != nil {
		t.Fatalf("append event: %v", err)
	}

	events, err := queue.Load()
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "test" {
		t.Fatalf("unexpected event type %q", events[0].Type)
	}

	second := api.Event{ID: "2", Type: "second", Timestamp: time.Unix(1700000100, 0)}
	if err := queue.Append(second); err != nil {
		t.Fatalf("append second event: %v", err)
	}

	events, err = queue.Load()
	if err != nil {
		t.Fatalf("reload events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if err := queue.Replace(nil); err != nil {
		t.Fatalf("replace events: %v", err)
	}
	events, err = queue.Load()
	if err != nil {
		t.Fatalf("load after replace: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected queue to be empty, got %d", len(events))
	}
}
