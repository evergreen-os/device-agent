package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/evergreen-os/device-agent/internal/util"
	"github.com/evergreen-os/device-agent/pkg/api"
)

// Queue persists device state snapshots until successfully reported.
type Queue struct {
	path string
	mu   sync.Mutex
}

// NewQueue creates a new queue at the specified path.
func NewQueue(path string) *Queue {
	return &Queue{path: path}
}

// Load returns queued snapshots without modifying the queue.
func (q *Queue) Load() ([]api.DeviceState, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.readLocked()
}

// Append adds a snapshot to the queue.
func (q *Queue) Append(state api.DeviceState) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	states, err := q.readLocked()
	if err != nil {
		return err
	}
	states = append(states, state)
	return q.writeLocked(states)
}

// Replace overwrites the queue with the provided snapshots.
func (q *Queue) Replace(states []api.DeviceState) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.writeLocked(states)
}

func (q *Queue) readLocked() ([]api.DeviceState, error) {
	data, err := os.ReadFile(q.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state queue: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var states []api.DeviceState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, fmt.Errorf("decode state queue: %w", err)
	}
	return states, nil
}

func (q *Queue) writeLocked(states []api.DeviceState) error {
	data, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state queue: %w", err)
	}
	if err := util.EnsureParentDir(q.path, 0o700); err != nil {
		return err
	}
	tmp := q.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write state queue: %w", err)
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return fmt.Errorf("commit state queue: %w", err)
	}
	return nil
}
