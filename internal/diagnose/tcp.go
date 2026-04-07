package diagnose

import (
	"context"
	"net"
	"strings"
	"time"
)

const tcpTimeout = 10 * time.Second

func CheckTCP(ctx context.Context, host, port string) ConnectionInfo {
	addr := net.JoinHostPort(host, port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: tcpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return classifyTCPError(err, latency)
	}

	// 提取远端 IP
	ip := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	conn.Close()

	return ConnectionInfo{
		Status:    "ok",
		LatencyMs: latency,
		IP:        ip,
	}
}

func classifyTCPError(err error, latencyMs int64) ConnectionInfo {
	errStr := err.Error()

	status := "error"
	switch {
	case isTimeout(err):
		status = "timeout"
	case strings.Contains(errStr, "connection refused"):
		status = "refused"
	case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "server misbehaving"):
		status = "dns_error"
	case strings.Contains(errStr, "connection reset"):
		status = "reset"
	}

	return ConnectionInfo{
		Status:    status,
		LatencyMs: latencyMs,
		Error:     errStr,
	}
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
