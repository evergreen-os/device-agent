package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/evergreen-os/device-agent/pkg/api"
)

// Verifier validates policy signatures using a pinned public key.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier loads an ed25519 public key from PEM or raw bytes.
func NewVerifier(path string) (*Verifier, error) {
	if path == "" {
		return nil, errors.New("public key path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	key, err := parsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return &Verifier{pub: key}, nil
}

func parsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T", key)
		}
		return pub, nil
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}
	return nil, fmt.Errorf("unsupported key encoding")
}

// Verify checks the signature on the policy envelope.
func (v *Verifier) Verify(envelope api.PolicyEnvelope) error {
	if len(v.pub) == 0 {
		return errors.New("public key not loaded")
	}
	if envelope.Signature == "" {
		return errors.New("policy signature missing")
	}
	payload, err := json.Marshal(envelope.Policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.pub, payload, sig) {
		return errors.New("invalid policy signature")
	}
	return nil
}
