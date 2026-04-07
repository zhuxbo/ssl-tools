package diagnose

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

const tlsTimeout = 10 * time.Second

func DoTLSHandshake(ctx context.Context, host, port string) TLSHandshakeResult {
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: tlsTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSHandshakeResult{HandshakeError: fmt.Errorf("TCP 连接失败: %w", err)}
	}

	start := time.Now()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})

	err = tlsConn.HandshakeContext(ctx)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		conn.Close()
		return TLSHandshakeResult{HandshakeError: err, LatencyMs: latency}
	}

	state := tlsConn.ConnectionState()
	tlsConn.Close()

	return TLSHandshakeResult{
		Protocol:     formatTLSVersion(state.Version),
		CipherSuite:  tls.CipherSuiteName(state.CipherSuite),
		Certificates: state.PeerCertificates,
		LatencyMs:    latency,
		ALPN:         state.NegotiatedProtocol,
		OCSPStapled:  len(state.OCSPResponse) > 0,
	}
}

func VerifyTLS(ctx context.Context, host, port string) error {
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: tlsTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP 连接失败: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
	})

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return err
	}

	tlsConn.Close()
	return nil
}

func formatTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
