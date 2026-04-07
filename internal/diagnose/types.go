package diagnose

import "crypto/x509"

// SSE 事件名常量
const (
	EventOverview    = "overview"
	EventDetails     = "details"
	EventCertificate = "certificate"
	EventProtocols   = "protocols"
	EventDone        = "done"
	EventError       = "error"
)

// OverviewResult 概览数据
type OverviewResult struct {
	Connection  ConnectionInfo `json:"connection"`
	CertStatus  string        `json:"cert_status"`
	Validity    *Validity     `json:"validity"`
	Protocol    string        `json:"protocol"`
	CipherSuite string        `json:"cipher_suite,omitempty"`
	Issues      []Issue       `json:"issues"`
}

type ConnectionInfo struct {
	Status    string `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	IP        string `json:"ip,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Validity struct {
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
}

type Issue struct {
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Impact     string `json:"impact"`
	Suggestion string `json:"suggestion"`
}

type CertificateResult struct {
	Subject            string      `json:"subject"`
	SAN                []string    `json:"san"`
	Issuer             string      `json:"issuer"`
	Organization       string      `json:"organization,omitempty"`
	Validity           Validity    `json:"validity"`
	CertType           string      `json:"cert_type"`
	IsWildcard         bool        `json:"is_wildcard"`
	Key                KeyInfo     `json:"key"`
	NotBeforeTS        int64       `json:"not_before_ts"`
	NotAfterTS         int64       `json:"not_after_ts"`
	SignatureAlgorithm string      `json:"signature_algorithm"`
	Fingerprint        string      `json:"fingerprint"`
	SerialNumber       string      `json:"serial_number"`
	OCSPServers        []string    `json:"ocsp_servers,omitempty"`
	SCTCount           int         `json:"sct_count"`
	Chain              []ChainCert `json:"chain"`
}

type KeyInfo struct {
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size"`
}

type ChainCert struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// DetailsResult 连接详情（从已有握手 + 一次 HTTP 请求获取）
type DetailsResult struct {
	IP          string `json:"ip"`
	Server      string `json:"server"`
	StatusCode  int    `json:"status_code"`
	StatusIssue *Issue `json:"status_issue,omitempty"`
	HTTP2       bool   `json:"http2"`
	HSTS        string `json:"hsts,omitempty"`
	OCSPStapled bool   `json:"ocsp_stapled"`
}

// ProtocolsResult 协议与加密（多版本探测，延迟输出）
type ProtocolsResult struct {
	Supported     []ProtocolVersion `json:"supported"`
	CipherSuites  []CipherSuite    `json:"cipher_suites"`
	InsecureItems []string          `json:"insecure_items,omitempty"`
}

type ProtocolVersion struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
}

type CipherSuite struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Secure  bool   `json:"secure"`
}

type DiagnoseTarget struct {
	Host     string
	Port     string
	Original string
}

// 内部使用
type TLSHandshakeResult struct {
	Protocol       string
	CipherSuite    string
	Certificates   []*x509.Certificate
	HandshakeError error
	LatencyMs      int64
	ALPN           string // "h2", "http/1.1"
	OCSPStapled    bool
}
