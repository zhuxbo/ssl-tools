package diagnose

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// QuickHTTPCheck 快速 HTTP 请求，获取状态码、Server 头、HSTS
func QuickHTTPCheck(ctx context.Context, host, port string) (statusCode int, server string, hsts string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var targetURL string
	if port == "443" {
		targetURL = fmt.Sprintf("https://%s/", host)
	} else {
		targetURL = fmt.Sprintf("https://%s:%s/", host, port)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "SSL-Tools/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	server = resp.Header.Get("Server")
	hsts = resp.Header.Get("Strict-Transport-Security")
	return
}
