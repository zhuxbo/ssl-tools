package diagnose

import (
	"context"
	"testing"
)

func TestTLSHandshake_ValidCert(t *testing.T) {
	result := DoTLSHandshake(context.Background(), "google.com", "443")
	if result.HandshakeError != nil {
		t.Fatalf("unexpected handshake error: %v", result.HandshakeError)
	}
	if len(result.Certificates) == 0 {
		t.Error("expected certificates, got none")
	}
	if result.Protocol == "" {
		t.Error("expected protocol version, got empty")
	}
}

func TestTLSHandshake_ExpiredCert(t *testing.T) {
	result := DoTLSHandshake(context.Background(), "expired.badssl.com", "443")
	if len(result.Certificates) == 0 {
		t.Error("expected certificates even for expired cert, got none")
	}
}

func TestTLSHandshake_SelfSigned(t *testing.T) {
	result := DoTLSHandshake(context.Background(), "self-signed.badssl.com", "443")
	if len(result.Certificates) == 0 {
		t.Error("expected certificates even for self-signed cert, got none")
	}
}
