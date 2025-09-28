package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

// Client communicates with the Evergreen backend.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// Option allows customizing the client.
type Option func(*Client)

// WithHTTPClient sets a custom http.Client.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.httpClient = c
	}
}

// New creates a new API client.
func New(base string, opts ...Option) (*Client, error) {
	if base == "" {
		return nil, errors.New("base URL required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	c := &Client{
		baseURL:    u,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// EnrollDeviceRequest contains hardware facts used for enrollment.
type EnrollDeviceRequest struct {
	SerialNumber string `json:"serial"`
	Model        string `json:"model"`
	CPUModel     string `json:"cpu_model"`
	CPUCount     int    `json:"cpu_count"`
	TotalRAM     uint64 `json:"total_ram_bytes"`
	HasTPM       bool   `json:"has_tpm"`
	PreSharedKey string `json:"pre_shared_key,omitempty"`
}

// EnrollDeviceResponse is returned after successful enrollment.
type EnrollDeviceResponse struct {
	DeviceID    string         `json:"device_id"`
	DeviceToken string         `json:"device_token"`
	Policy      PolicyEnvelope `json:"policy"`
}

// PolicyEnvelope wraps a policy bundle with metadata.
type PolicyEnvelope struct {
	Version     string         `json:"version"`
	Signature   string         `json:"signature"`
	Policy      PolicyDocument `json:"policy"`
	DeviceToken string         `json:"device_token,omitempty"`
}

// PolicyDocument defines the policy data enforced by the agent.
type PolicyDocument struct {
	Apps     AppsPolicy     `json:"apps"`
	Updates  UpdatePolicy   `json:"updates"`
	Browser  BrowserPolicy  `json:"browser"`
	Network  NetworkPolicy  `json:"network"`
	Security SecurityPolicy `json:"security"`
}

type AppsPolicy struct {
	Required []AppDefinition `json:"required"`
}

type AppDefinition struct {
	ID     string `json:"id"`
	Branch string `json:"branch"`
	Source string `json:"source"`
}

type UpdatePolicy struct {
	Channel        string   `json:"channel"`
	RebootRequired bool     `json:"reboot_required"`
	Maintenance    []string `json:"maintenance_windows"`
}

type BrowserPolicy struct {
	Homepage         string     `json:"homepage"`
	Extensions       []string   `json:"extensions"`
	AllowDevTools    bool       `json:"allow_dev_tools"`
	ManagedBookmarks []Bookmark `json:"managed_bookmarks"`
}

type Bookmark struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type NetworkPolicy struct {
	WiFi   []WiFiNetwork `json:"wifi"`
	VPNs   []VPNProfile  `json:"vpns"`
	VPNDNS []string      `json:"vpn_dns"`
}

type WiFiNetwork struct {
	SSID       string            `json:"ssid"`
	Passphrase string            `json:"passphrase"`
	Security   string            `json:"security"`
	Hidden     bool              `json:"hidden"`
	Metered    bool              `json:"metered"`
	EAP        map[string]string `json:"eap"`
}

type VPNProfile struct {
	Name        string            `json:"name"`
	ServiceType string            `json:"service_type"`
	Data        map[string]string `json:"data"`
	Secrets     map[string]string `json:"secrets"`
	AutoConnect bool              `json:"auto_connect"`
}

type SecurityPolicy struct {
	SELinuxEnforce bool     `json:"selinux_enforce"`
	SSHEnabled     bool     `json:"ssh_enabled"`
	USBGuard       bool     `json:"usbguard"`
	USBGuardRules  []string `json:"usbguard_rules"`
	AllowRootLogin bool     `json:"allow_root_login"`
}

// PullPolicyRequest requests a new policy if changed.
type PullPolicyRequest struct {
	CurrentVersion string `json:"current_version"`
}

// ReportStateRequest contains aggregated state information.
type ReportStateRequest struct {
	DeviceID string      `json:"device_id"`
	State    DeviceState `json:"state"`
}

// DeviceState is reported to the backend.
type DeviceState struct {
	Timestamp      time.Time      `json:"timestamp"`
	InstalledApps  []InstalledApp `json:"installed_apps"`
	UpdateStatus   string         `json:"update_status"`
	DiskTotalBytes uint64         `json:"disk_total_bytes"`
	DiskFreeBytes  uint64         `json:"disk_free_bytes"`
	BatteryPercent float64        `json:"battery_percent"`
	LastError      string         `json:"last_error"`
}

// InstalledApp describes an installed Flatpak.
type InstalledApp struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Branch  string `json:"branch"`
}

// Event represents an event emitted by the agent.
type Event struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// ReportEventsRequest batches events.
type ReportEventsRequest struct {
	DeviceID string  `json:"device_id"`
	Events   []Event `json:"events"`
}

// AttestBootRequest uploads TPM attestation evidence.
type AttestBootRequest struct {
	DeviceID string              `json:"device_id"`
	Evidence AttestationEvidence `json:"evidence"`
}

// AttestationEvidence contains TPM attestation material.
type AttestationEvidence struct {
	Nonce    string             `json:"nonce"`
	AKPublic string             `json:"ak_public"`
	Quotes   []AttestationQuote `json:"quotes"`
	PCRs     map[string]string  `json:"pcrs"`
}

// AttestationQuote represents a single TPM quote and signature.
type AttestationQuote struct {
	Version   string `json:"version"`
	Quote     string `json:"quote"`
	Signature string `json:"signature"`
}

// ErrNotModified indicates the policy has not changed.
var ErrNotModified = errors.New("policy not modified")

func (c *Client) buildURL(parts ...string) string {
	u := *c.baseURL
	u.Path = path.Join(append([]string{c.baseURL.Path}, parts...)...)
	return u.String()
}

func (c *Client) doJSON(ctx context.Context, method, url string, body any, out any, headers http.Header) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return ErrNotModified
	}
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api error %d: %s", resp.StatusCode, string(data))
	}
	if out != nil {
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// EnrollDevice performs the enrollment RPC.
func (c *Client) EnrollDevice(ctx context.Context, req EnrollDeviceRequest) (EnrollDeviceResponse, error) {
	var resp EnrollDeviceResponse
	url := c.buildURL("api", "v1", "devices", "enroll")
	if err := c.doJSON(ctx, http.MethodPost, url, req, &resp, nil); err != nil {
		return EnrollDeviceResponse{}, err
	}
	return resp, nil
}

// PullPolicy retrieves the latest policy bundle.
func (c *Client) PullPolicy(ctx context.Context, token, currentVersion string) (PolicyEnvelope, error) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	url := c.buildURL("api", "v1", "devices", "policy")
	var resp PolicyEnvelope
	req := PullPolicyRequest{CurrentVersion: currentVersion}
	if err := c.doJSON(ctx, http.MethodPost, url, req, &resp, headers); err != nil {
		return PolicyEnvelope{}, err
	}
	return resp, nil
}

// ReportState sends device state to the backend.
func (c *Client) ReportState(ctx context.Context, token string, req ReportStateRequest) error {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	url := c.buildURL("api", "v1", "devices", "state")
	return c.doJSON(ctx, http.MethodPost, url, req, nil, headers)
}

// ReportEvents sends queued events.
func (c *Client) ReportEvents(ctx context.Context, token string, req ReportEventsRequest) error {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	url := c.buildURL("api", "v1", "devices", "events")
	return c.doJSON(ctx, http.MethodPost, url, req, nil, headers)
}

// AttestBoot sends TPM attestation data for the current boot.
func (c *Client) AttestBoot(ctx context.Context, token string, req AttestBootRequest) error {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	url := c.buildURL("api", "v1", "devices", "attest")
	return c.doJSON(ctx, http.MethodPost, url, req, nil, headers)
}
