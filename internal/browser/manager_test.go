package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"log/slog"

	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestApplyWritesChromiumPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr := NewManager(logger, path)

	policy := api.BrowserPolicy{
		Homepage:      "https://example.com",
		Extensions:    []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		AllowDevTools: false,
		ManagedBookmarks: []api.Bookmark{{
			Name: "Docs",
			URL:  "https://docs.example.com",
		}},
	}
	events, err := mgr.Apply(policy)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if cfg["HomepageLocation"] != "https://example.com" {
		t.Fatalf("unexpected homepage: %v", cfg["HomepageLocation"])
	}
	if cfg["DeveloperToolsAvailability"].(float64) != 2 {
		t.Fatalf("expected devtools disabled")
	}
}
