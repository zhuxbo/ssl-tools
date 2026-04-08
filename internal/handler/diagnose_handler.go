package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"ssl-tools/internal/diagnose"
)

type DiagnoseHandler struct{}

func NewDiagnoseHandler() *DiagnoseHandler {
	return &DiagnoseHandler{}
}

func (h *DiagnoseHandler) Handle(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if host == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}
	if port == "" {
		port = "443"
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	// 阶段 1+2: TCP + TLS → overview，然后 details + certificate
	connInfo, tlsResult, tlsOK := h.diagnoseOverview(ctx, w, flusher, host, port)
	if ctx.Err() != nil {
		return
	}

	// 阶段 3: 连接详情（紧跟概览）
	if connInfo.Status == "ok" {
		h.diagnoseDetails(ctx, w, flusher, host, port, connInfo, tlsResult)
	}
	if ctx.Err() != nil {
		return
	}

	// 阶段 4: 证书信息
	if tlsOK {
		certResult := diagnose.AnalyzeCert(tlsResult.Certificates, host)
		sendSSE(w, flusher, diagnose.EventCertificate, certResult)
	}
	if ctx.Err() != nil {
		return
	}

	// 阶段 5: 协议与加密（延迟，多版本探测）
	if connInfo.Status == "ok" {
		h.diagnoseProtocols(ctx, w, flusher, host, port)
	}

	sendSSE(w, flusher, diagnose.EventDone, struct{}{})
}

func (h *DiagnoseHandler) diagnoseOverview(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, host, port string) (diagnose.ConnectionInfo, diagnose.TLSHandshakeResult, bool) {
	connInfo := diagnose.CheckTCP(ctx, host, port)
	var tlsResult diagnose.TLSHandshakeResult

	if connInfo.Status != "ok" {
		overview := diagnose.OverviewResult{
			Connection: connInfo,
			CertStatus: "no_cert",
			Issues: []diagnose.Issue{{
				Severity:   "error",
				Title:      classifyConnectionError(connInfo),
				Impact:     "无法建立 TCP 连接，后续诊断无法进行",
				Suggestion: connectionSuggestion(connInfo),
			}},
		}
		sendSSE(w, flusher, diagnose.EventOverview, overview)
		return connInfo, tlsResult, false
	}

	tlsResult = diagnose.DoTLSHandshake(ctx, host, port)
	verifyErr := diagnose.VerifyTLS(ctx, host, port)

	if tlsResult.HandshakeError != nil {
		// TLS 失败：连接状态标记为 tls_failed
		connInfo.Status = "tls_failed"
		connInfo.Error = tlsResult.HandshakeError.Error()
		overview := diagnose.OverviewResult{
			Connection: connInfo,
			CertStatus: "no_cert",
			Issues: []diagnose.Issue{{
				Severity:   "error",
				Title:      "TLS 握手失败",
				Impact:     "无法建立安全连接",
				Suggestion: fmt.Sprintf("错误: %s。可能原因: 服务器未配置 SSL、端口不支持 TLS、被防火墙拦截", tlsResult.HandshakeError),
			}},
		}
		sendSSE(w, flusher, diagnose.EventOverview, overview)
		return connInfo, tlsResult, false
	}

	connInfo.LatencyMs += tlsResult.LatencyMs

	issues := diagnose.IdentifyIssues(tlsResult.Certificates, host, verifyErr)
	certStatus := determineCertStatus(issues)

	certResult := diagnose.AnalyzeCert(tlsResult.Certificates, host)

	overview := diagnose.OverviewResult{
		Connection:  connInfo,
		CertStatus:  certStatus,
		Validity:    &certResult.Validity,
		Protocol:    tlsResult.Protocol,
		CipherSuite: tlsResult.CipherSuite,
		Issues:      issues,
	}

	sendSSE(w, flusher, diagnose.EventOverview, overview)
	return connInfo, tlsResult, true
}

func (h *DiagnoseHandler) diagnoseDetails(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, host, port string, connInfo diagnose.ConnectionInfo, tlsResult diagnose.TLSHandshakeResult) {
	statusCode, server, hsts := diagnose.QuickHTTPCheck(ctx, host, port)

	details := diagnose.DetailsResult{
		IP:          connInfo.IP,
		Server:      server,
		StatusCode:  statusCode,
		HTTP2:       tlsResult.ALPN == "h2",
		HSTS:        hsts,
		OCSPStapled: tlsResult.OCSPStapled,
	}

	if issue := diagnose.HTTPStatusIssue(statusCode); issue != nil {
		details.StatusIssue = issue
	}

	sendSSE(w, flusher, diagnose.EventDetails, details)
}

func (h *DiagnoseHandler) diagnoseProtocols(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, host, port string) {
	result := diagnose.ProbeProtocols(ctx, host, port)
	sendSSE(w, flusher, diagnose.EventProtocols, result)
}

func sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("SSE marshal error: %v", err)
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonData)
	flusher.Flush()
}

func determineCertStatus(issues []diagnose.Issue) string {
	for _, iss := range issues {
		if iss.Severity == "error" {
			switch {
			case strings.Contains(iss.Title, "过期"):
				return "expired"
			case strings.Contains(iss.Title, "不匹配"):
				return "mismatch"
			case strings.Contains(iss.Title, "自签名"):
				return "self_signed"
			case strings.Contains(iss.Title, "链不完整"):
				return "chain_incomplete"
			case strings.Contains(iss.Title, "无法获取"):
				return "no_cert"
			default:
				return "untrusted"
			}
		}
	}
	return "valid"
}

func classifyConnectionError(info diagnose.ConnectionInfo) string {
	switch info.Status {
	case "timeout":
		return "连接超时"
	case "refused":
		return "连接被拒绝"
	case "dns_error":
		return "DNS 解析失败"
	case "reset":
		return "连接被重置"
	default:
		return "连接失败"
	}
}

func connectionSuggestion(info diagnose.ConnectionInfo) string {
	switch info.Status {
	case "timeout":
		return "可能原因: 端口未开放、防火墙拦截、服务器不可达。排查: 检查安全组/防火墙规则是否放行该端口"
	case "refused":
		return "可能原因: 目标端口无服务监听。排查: 确认 Web 服务是否启动并监听正确端口"
	case "dns_error":
		return "可能原因: 域名未注册、DNS 记录未配置、DNS 服务器故障。排查: 使用 nslookup 或 dig 检查域名解析"
	case "reset":
		return "可能原因: 防火墙主动拒绝、GFW 拦截、服务器安全策略。排查: 尝试从其他区域访问以确认是否为区域性拦截"
	default:
		return "请检查目标服务器是否可达"
	}
}
