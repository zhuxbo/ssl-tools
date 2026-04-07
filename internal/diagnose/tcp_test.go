package diagnose

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestCheckTCP_Success(t *testing.T) {
	result := CheckTCP(context.Background(), "google.com", "443")
	if result.Status != "ok" {
		t.Errorf("expected status ok, got %q, error: %s", result.Status, result.Error)
	}
	if result.LatencyMs <= 0 {
		t.Errorf("expected positive latency, got %d", result.LatencyMs)
	}
}

func TestCheckTCP_Refused(t *testing.T) {
	result := CheckTCP(context.Background(), "127.0.0.1", "19999")
	if result.Status == "ok" {
		t.Errorf("expected connection failure, got ok")
	}
}

// TestCheckTCP_DNSError 验证 DNS 错误分类逻辑（不依赖外部 DNS 解析）
func TestCheckTCP_DNSError(t *testing.T) {
	// 直接测试分类逻辑，避免 DNS 劫持导致的测试不稳定
	dnsErr := &net.DNSError{
		Err:        "no such host",
		Name:       "this-domain-does-not-exist-12345.com",
		IsNotFound: true,
	}
	result := classifyTCPError(dnsErr, 100)
	if result.Status != "dns_error" {
		t.Errorf("expected dns_error, got %q", result.Status)
	}
}

func TestClassifyTCPError_Refused(t *testing.T) {
	err := errors.New("connect: connection refused")
	result := classifyTCPError(err, 5)
	if result.Status != "refused" {
		t.Errorf("expected refused, got %q", result.Status)
	}
}

func TestClassifyTCPError_Reset(t *testing.T) {
	err := errors.New("read: connection reset by peer")
	result := classifyTCPError(err, 5)
	if result.Status != "reset" {
		t.Errorf("expected reset, got %q", result.Status)
	}
}

func TestClassifyTCPError_Timeout(t *testing.T) {
	err := &net.OpError{
		Op:  "dial",
		Err: &timeoutError{},
	}
	result := classifyTCPError(err, 10000)
	if result.Status != "timeout" {
		t.Errorf("expected timeout, got %q", result.Status)
	}
}

// timeoutError 实现 net.Error 接口，模拟超时错误
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
