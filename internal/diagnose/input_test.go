package diagnose

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"plain domain", "example.com", "example.com", "443", false},
		{"domain with port", "example.com:8443", "example.com", "8443", false},
		{"https url", "https://example.com/path?q=1", "example.com", "443", false},
		{"https url with port", "https://example.com:8443/path", "example.com", "8443", false},
		{"http url", "http://example.com", "example.com", "443", false},
		{"ip address", "1.2.3.4", "1.2.3.4", "443", false},
		{"ip with port", "1.2.3.4:8443", "1.2.3.4", "8443", false},
		{"https ip url", "https://1.2.3.4:8443/path", "1.2.3.4", "8443", false},
		{"with spaces", "  example.com  ", "example.com", "443", false},
		{"empty input", "", "", "", true},
		{"only spaces", "   ", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := ParseTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if target.Host != tt.wantHost {
				t.Errorf("host: got %q, want %q", target.Host, tt.wantHost)
			}
			if target.Port != tt.wantPort {
				t.Errorf("port: got %q, want %q", target.Port, tt.wantPort)
			}
		})
	}
}

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		name string
		host string
		port string
		want string
	}{
		{"default port", "example.com", "443", "example.com"},
		{"custom port", "example.com", "8443", "example.com:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := DiagnoseTarget{Host: tt.host, Port: tt.port}
			got := target.Format()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
