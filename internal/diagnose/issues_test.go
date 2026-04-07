package diagnose

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestIdentifyIssues_Expired(t *testing.T) {
	cert := makeCert("example.com", []string{"example.com"},
		time.Now().Add(-365*24*time.Hour), time.Now().Add(-1*24*time.Hour), false)
	issues := IdentifyIssues([]*x509.Certificate{cert}, "example.com", nil)
	found := false
	for _, iss := range issues {
		if iss.Severity == "error" && strings.Contains(iss.Title, "过期") {
			found = true
		}
	}
	if !found {
		t.Error("expected expired cert issue")
	}
}

func TestIdentifyIssues_Mismatch(t *testing.T) {
	cert := makeCert("other.com", []string{"other.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(90*24*time.Hour), false)
	issues := IdentifyIssues([]*x509.Certificate{cert}, "example.com", nil)
	found := false
	for _, iss := range issues {
		if iss.Severity == "error" && strings.Contains(iss.Title, "不匹配") {
			found = true
		}
	}
	if !found {
		t.Error("expected domain mismatch issue")
	}
}

func TestIdentifyIssues_ExpiringSoon(t *testing.T) {
	cert := makeCert("example.com", []string{"example.com"},
		time.Now().Add(-300*24*time.Hour), time.Now().Add(15*24*time.Hour), false)
	issues := IdentifyIssues([]*x509.Certificate{cert}, "example.com", nil)
	found := false
	for _, iss := range issues {
		if iss.Severity == "warning" && strings.Contains(iss.Title, "即将过期") {
			found = true
		}
	}
	if !found {
		t.Error("expected expiring soon warning")
	}
}

func TestIdentifyIssues_SelfSigned(t *testing.T) {
	cert := makeCert("example.com", []string{"example.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(90*24*time.Hour), false)
	issues := IdentifyIssues([]*x509.Certificate{cert}, "example.com", nil)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss.Title, "自签名") {
			found = true
		}
	}
	if !found {
		t.Error("expected self-signed issue")
	}
}

func TestHTTPStatusIssue(t *testing.T) {
	tests := []struct {
		code    int
		wantNil bool
	}{
		{200, true},
		{301, true},
		{302, true},
		{403, false},
		{500, false},
		{502, false},
		{503, false},
	}
	for _, tt := range tests {
		issue := HTTPStatusIssue(tt.code)
		if tt.wantNil && issue != nil {
			t.Errorf("code %d: expected nil issue, got %+v", tt.code, issue)
		}
		if !tt.wantNil && issue == nil {
			t.Errorf("code %d: expected issue, got nil", tt.code)
		}
	}
}
