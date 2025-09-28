package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/evergreen-os/device-agent/pkg/api"
)

func TestVerifierVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	verifier, err := NewVerifier(keyPath)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	document := api.PolicyDocument{}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	signature := ed25519.Sign(priv, payload)
	envelope := api.PolicyEnvelope{Policy: document, Signature: base64.StdEncoding.EncodeToString(signature)}
	if err := verifier.Verify(envelope); err != nil {
		t.Fatalf("verify policy: %v", err)
	}

	envelope.Signature = base64.StdEncoding.EncodeToString([]byte("invalid"))
	if err := verifier.Verify(envelope); err == nil {
		t.Fatalf("expected verification failure")
	}
}
