package diagnose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func makeCert(cn string, san []string, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     san,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         isCA,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func TestAnalyzeCert_Valid(t *testing.T) {
	cert := makeCert("example.com", []string{"example.com", "*.example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(90*24*time.Hour), false)
	result := AnalyzeCert([]*x509.Certificate{cert}, "example.com")
	if result.Subject != "example.com" {
		t.Errorf("subject: got %q, want %q", result.Subject, "example.com")
	}
	if len(result.SAN) != 2 {
		t.Errorf("san count: got %d, want 2", len(result.SAN))
	}
	if result.Validity.DaysLeft < 0 {
		t.Error("expected positive days_left for valid cert")
	}
	if result.Key.Algorithm != "ECDSA" {
		t.Errorf("key algorithm: got %q, want ECDSA", result.Key.Algorithm)
	}
}

func TestAnalyzeCert_Expired(t *testing.T) {
	cert := makeCert("example.com", []string{"example.com"},
		time.Now().Add(-365*24*time.Hour), time.Now().Add(-1*24*time.Hour), false)
	result := AnalyzeCert([]*x509.Certificate{cert}, "example.com")
	if result.Validity.DaysLeft >= 0 {
		t.Errorf("expected negative days_left for expired cert, got %d", result.Validity.DaysLeft)
	}
}

func TestAnalyzeCert_Chain(t *testing.T) {
	leaf := makeCert("example.com", []string{"example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(90*24*time.Hour), false)
	intermediate := makeCert("Intermediate CA", nil,
		time.Now().Add(-365*24*time.Hour), time.Now().Add(365*24*time.Hour), true)
	result := AnalyzeCert([]*x509.Certificate{leaf, intermediate}, "example.com")
	if len(result.Chain) != 2 {
		t.Errorf("chain length: got %d, want 2", len(result.Chain))
	}
}
