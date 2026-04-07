package diagnose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math"
	"strings"
	"time"
)

// CAB Forum 策略 OID
var (
	oidEV = asn1.ObjectIdentifier{2, 23, 140, 1, 1}
	oidOV = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	oidDV = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	// SCT 扩展 OID (RFC 6962)
	oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func AnalyzeCert(certs []*x509.Certificate, host string) CertificateResult {
	if len(certs) == 0 {
		return CertificateResult{}
	}
	leaf := certs[0]
	now := time.Now()
	daysLeft := int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
	fingerprint := sha256.Sum256(leaf.Raw)
	fpStr := formatFingerprint(fingerprint[:])
	serial := fmt.Sprintf("%X", leaf.SerialNumber)
	keyInfo := extractKeyInfo(leaf)

	chain := make([]ChainCert, len(certs))
	for i, c := range certs {
		chain[i] = ChainCert{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName}
	}

	// 组织机构
	org := ""
	if len(leaf.Subject.Organization) > 0 {
		org = strings.Join(leaf.Subject.Organization, ", ")
	}

	// 证书类型推断
	certType := detectCertType(leaf)

	// 通配符检测
	isWildcard := false
	for _, san := range leaf.DNSNames {
		if strings.HasPrefix(san, "*.") {
			isWildcard = true
			break
		}
	}
	if strings.HasPrefix(leaf.Subject.CommonName, "*.") {
		isWildcard = true
	}

	// SCT 数量
	sctCount := countSCTs(leaf)

	return CertificateResult{
		Subject:            leaf.Subject.CommonName,
		SAN:                leaf.DNSNames,
		Issuer:             leaf.Issuer.CommonName,
		Organization:       org,
		Validity:           Validity{NotBefore: leaf.NotBefore.Format("2006-01-02"), NotAfter: leaf.NotAfter.Format("2006-01-02"), DaysLeft: daysLeft},
		NotBeforeTS:        leaf.NotBefore.Unix(),
		NotAfterTS:         leaf.NotAfter.Unix(),
		CertType:           certType,
		IsWildcard:         isWildcard,
		Key:                keyInfo,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		Fingerprint:        fpStr,
		SerialNumber:       serial,
		OCSPServers:        leaf.OCSPServer,
		SCTCount:           sctCount,
		Chain:              chain,
	}
}

func detectCertType(cert *x509.Certificate) string {
	for _, policy := range cert.PolicyIdentifiers {
		if policy.Equal(oidEV) {
			return "EV"
		}
	}
	for _, policy := range cert.PolicyIdentifiers {
		if policy.Equal(oidOV) {
			return "OV"
		}
	}
	for _, policy := range cert.PolicyIdentifiers {
		if policy.Equal(oidDV) {
			return "DV"
		}
	}
	// 回退推断：有组织信息通常是 OV/EV
	if len(cert.Subject.Organization) > 0 && cert.Subject.Organization[0] != "" {
		return "OV"
	}
	return "DV"
}

func countSCTs(cert *x509.Certificate) int {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			// SCT 列表是 TLS 编码，每个 SCT 有 2 字节长度前缀
			// 简单计数：跳过前 2 字节总长度，然后逐个读取
			data := ext.Value
			if len(data) < 4 {
				return 0
			}
			// 外层是 OCTET STRING 包装，解包
			var raw asn1.RawValue
			if _, err := asn1.Unmarshal(data, &raw); err == nil {
				data = raw.Bytes
			}
			if len(data) < 2 {
				return 0
			}
			listLen := int(data[0])<<8 | int(data[1])
			data = data[2:]
			if len(data) < listLen {
				return 0
			}
			count := 0
			for len(data) >= 2 {
				sctLen := int(data[0])<<8 | int(data[1])
				data = data[2:]
				if len(data) < sctLen {
					break
				}
				data = data[sctLen:]
				count++
			}
			return count
		}
	}
	return 0
}

func extractKeyInfo(cert *x509.Certificate) KeyInfo {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return KeyInfo{Algorithm: "RSA", Size: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeyInfo{Algorithm: "ECDSA", Size: pub.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return KeyInfo{Algorithm: "Ed25519", Size: 256}
	default:
		return KeyInfo{Algorithm: "Unknown", Size: 0}
	}
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
