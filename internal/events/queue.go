package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Queue persists events locally until flushed to the backend.
type Queue struct {
	path string
	mu   sync.Mutex
}

// NewQueue creates a new queue backed by the provided file path.
func NewQueue(path string) *Queue {
	return &Queue{path: path}
}

// Load reads existing events from disk.
func (q *Queue) Load() ([]api.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	data, err := os.ReadFile(q.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read events: %w", err)
	}
	var events []api.Event
	if len(data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}
	return events, nil
}

// Append adds events to the queue and persists them.
func (q *Queue) Append(events ...api.Event) error {
	if len(events) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	existing, err := q.readLocked()
	if err != nil {
		return err
	}
	existing = append(existing, events...)
	return q.writeLocked(existing)
}

// Replace writes the provided events replacing the contents.
func (q *Queue) Replace(events []api.Event) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.writeLocked(events)
}

func (q *Queue) readLocked() ([]api.Event, error) {
	data, err := os.ReadFile(q.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read events: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var events []api.Event
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}
	return events, nil
}

func (q *Queue) writeLocked(events []api.Event) error {
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("encode events: %w", err)
	}
	if err := util.EnsureParentDir(q.path, 0o700); err != nil {
		return err
	}
	tmpPath := q.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write temp events: %w", err)
	}
	if err := os.Rename(tmpPath, q.path); err != nil {
		return fmt.Errorf("rename events: %w", err)
	}
	return nil
}

// NewEvent helper to create event objects with timestamp.
func NewEvent(eventType string, payload any) api.Event {
	return api.Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}
}
