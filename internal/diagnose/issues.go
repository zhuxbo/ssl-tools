package diagnose

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

const expiryWarningDays = 30

func IdentifyIssues(certs []*x509.Certificate, host string, verifyErr error) []Issue {
	var issues []Issue

	if len(certs) == 0 {
		issues = append(issues, Issue{
			Severity: "error", Title: "无法获取证书",
			Impact: "无法建立安全连接", Suggestion: "检查服务器是否配置了 SSL 证书",
		})
		return issues
	}

	leaf := certs[0]
	now := time.Now()

	// 证书过期
	if now.After(leaf.NotAfter) {
		days := int(now.Sub(leaf.NotAfter).Hours() / 24)
		issues = append(issues, Issue{
			Severity: "error", Title: "证书已过期",
			Impact:     "所有浏览器将显示安全警告，用户无法正常访问",
			Suggestion: fmt.Sprintf("证书已过期 %d 天，请续费或重新签发 SSL 证书", days),
		})
	} else if now.Before(leaf.NotBefore) {
		issues = append(issues, Issue{
			Severity: "error", Title: "证书尚未生效",
			Impact:     "浏览器将拒绝此证书",
			Suggestion: fmt.Sprintf("证书生效时间为 %s，请检查服务器时间是否正确", leaf.NotBefore.Format("2006-01-02")),
		})
	} else {
		daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
		if daysLeft <= expiryWarningDays {
			issues = append(issues, Issue{
				Severity: "warning", Title: "证书即将过期",
				Impact:     fmt.Sprintf("证书将在 %d 天后过期，届时浏览器将显示安全警告", daysLeft),
				Suggestion: "请尽快续费或重新签发 SSL 证书",
			})
		}
	}

	// 域名不匹配
	if err := leaf.VerifyHostname(host); err != nil {
		issues = append(issues, Issue{
			Severity: "error", Title: "证书域名不匹配",
			Impact:     "浏览器将显示安全警告，证书不适用于此域名",
			Suggestion: fmt.Sprintf("证书 SAN 列表为 [%s]，不包含 %s", strings.Join(leaf.DNSNames, ", "), host),
		})
	}

	// 自签名检测
	if leaf.Issuer.CommonName == leaf.Subject.CommonName && len(certs) == 1 {
		issues = append(issues, Issue{
			Severity: "warning", Title: "自签名证书",
			Impact: "浏览器不信任自签名证书，将显示安全警告", Suggestion: "建议使用受信任的 CA 签发证书",
		})
	}

	// 证书链不完整
	if verifyErr != nil {
		errStr := verifyErr.Error()
		if strings.Contains(errStr, "certificate signed by unknown authority") {
			if leaf.Issuer.CommonName != leaf.Subject.CommonName {
				issues = append(issues, Issue{
					Severity: "error", Title: "证书链不完整",
					Impact: "部分客户端/设备无法建立安全连接", Suggestion: "请在服务器配置中添加中间证书",
				})
			}
		}
	}

	return issues
}

func HTTPStatusIssue(statusCode int) *Issue {
	if statusCode >= 200 && statusCode < 400 {
		return nil
	}

	issue := &Issue{Severity: "warning"}

	switch statusCode {
	case 400:
		issue.Title = "HTTP 400 Bad Request"
		issue.Impact = "服务器无法处理请求"
		issue.Suggestion = "可能原因: 请求格式错误、请求头过大。排查: 检查服务器的请求大小限制和 header 配置"
	case 403:
		issue.Title = "HTTP 403 Forbidden"
		issue.Impact = "服务器拒绝访问"
		issue.Suggestion = "可能原因: IP 被封、未备案被拦截、WAF 规则拦截、访问控制限制。排查: 检查防火墙规则和访问控制配置"
	case 404:
		issue.Title = "HTTP 404 Not Found"
		issue.Impact = "请求的页面不存在"
		issue.Suggestion = "可能原因: 域名绑定到服务器但未配置站点、站点根目录为空。排查: 检查 Web 服务器的站点配置"
	case 500:
		issue.Title = "HTTP 500 Internal Server Error"
		issue.Impact = "服务器内部错误"
		issue.Suggestion = "可能原因: 应用程序异常、配置错误。排查: 检查服务器错误日志"
	case 502:
		issue.Title = "HTTP 502 Bad Gateway"
		issue.Impact = "网关/代理收到无效的上游响应"
		issue.Suggestion = "可能原因: 上游服务未运行、上游服务崩溃、代理配置错误。排查: 检查 Nginx/CDN 的上游配置和后端服务状态"
	case 503:
		issue.Title = "HTTP 503 Service Unavailable"
		issue.Impact = "服务暂时不可用"
		issue.Suggestion = "可能原因: 服务器过载、服务维护中、后端服务未启动。排查: 检查服务进程状态和资源使用情况"
	case 504:
		issue.Title = "HTTP 504 Gateway Timeout"
		issue.Impact = "网关/代理等待上游超时"
		issue.Suggestion = "可能原因: 上游服务响应过慢、网络超时。排查: 检查上游服务性能和代理超时配置"
	case 520, 521, 522, 523, 524, 525, 526:
		issue.Title = fmt.Sprintf("HTTP %d (Cloudflare)", statusCode)
		issue.Impact = "Cloudflare 报告源站错误"
		issue.Suggestion = "可能原因: 源站 SSL 配置错误、源站不可达、Cloudflare 与源站之间的 TLS 握手失败。排查: 检查 Cloudflare SSL/TLS 设置和源站配置"
	default:
		issue.Title = fmt.Sprintf("HTTP %d", statusCode)
		issue.Impact = "服务器返回异常状态码"
		issue.Suggestion = "请检查 Web 服务器配置和应用日志"
	}

	return issue
}
