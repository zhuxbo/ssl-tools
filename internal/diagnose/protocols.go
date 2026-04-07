package diagnose

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

type protocolProbe struct {
	Name    string
	Version uint16
}

var protocolsToProbe = []protocolProbe{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

var insecureCipherKeywords = []string{"RC4", "3DES", "DES", "NULL", "EXPORT", "anon", "MD5"}

// ProbeProtocols 逐个探测 TLS 版本，同时获取每个版本协商的加密套件
func ProbeProtocols(ctx context.Context, host, port string) ProtocolsResult {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	supported := make([]ProtocolVersion, len(protocolsToProbe))
	var cipherSuites []CipherSuite

	for i, probe := range protocolsToProbe {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			supported[i] = ProtocolVersion{Name: probe.Name, Supported: false}
			continue
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         probe.Version,
			MaxVersion:         probe.Version,
		})

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			supported[i] = ProtocolVersion{Name: probe.Name, Supported: false}
			continue
		}

		state := tlsConn.ConnectionState()
		tlsConn.Close()
		supported[i] = ProtocolVersion{Name: probe.Name, Supported: true}

		cipherName := tls.CipherSuiteName(state.CipherSuite)
		cipherSuites = append(cipherSuites, CipherSuite{
			Name:    cipherName,
			Version: probe.Name,
			Secure:  isCipherSecure(cipherName),
		})
	}

	var insecureItems []string
	for _, p := range supported {
		if p.Supported && (p.Name == "TLS 1.0" || p.Name == "TLS 1.1") {
			insecureItems = append(insecureItems, p.Name+"（已废弃）")
		}
	}
	for _, cs := range cipherSuites {
		if !cs.Secure {
			insecureItems = append(insecureItems, cs.Name)
		}
	}

	return ProtocolsResult{
		Supported:     supported,
		CipherSuites:  cipherSuites,
		InsecureItems: insecureItems,
	}
}

func isCipherSecure(name string) bool {
	for _, keyword := range insecureCipherKeywords {
		if strings.Contains(name, keyword) {
			return false
		}
	}
	return true
}
