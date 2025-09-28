package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClientBuildURL(t *testing.T) {
	client, err := New("https://example.com/base/", WithHTTPClient(&http.Client{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	url := client.buildURL("api", "v1", "devices")
	expected := "https://example.com/base/api/v1/devices"
	if url != expected {
		t.Fatalf("expected %s, got %s", expected, url)
	}
}

func TestNewClientRequiresBase(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatalf("expected error for empty base URL")
	}
}

func TestAttestBoot(t *testing.T) {
	var gotAuth string
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	req := AttestBootRequest{DeviceID: "device", Evidence: AttestationEvidence{}}
	if err := client.AttestBoot(context.Background(), "token", req); err != nil {
		t.Fatalf("attest boot: %v", err)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("expected auth header, got %s", gotAuth)
	}
	if gotPath != "/api/v1/devices/attest" {
		t.Fatalf("unexpected path %s", gotPath)
	}
}
