package diagnose

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func ParseTarget(input string) (DiagnoseTarget, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return DiagnoseTarget{}, fmt.Errorf("输入不能为空")
	}
	original := input

	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return DiagnoseTarget{}, fmt.Errorf("无法解析 URL: %w", err)
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return DiagnoseTarget{Host: host, Port: port, Original: original}, nil
	}

	if strings.Count(input, ":") > 1 && !strings.Contains(input, "[") {
		return DiagnoseTarget{Host: input, Port: "443", Original: original}, nil
	}

	host, port, err := net.SplitHostPort(input)
	if err != nil {
		return DiagnoseTarget{Host: input, Port: "443", Original: original}, nil
	}
	return DiagnoseTarget{Host: host, Port: port, Original: original}, nil
}

func (t DiagnoseTarget) Format() string {
	if t.Port == "443" {
		return t.Host
	}
	return t.Host + ":" + t.Port
}
