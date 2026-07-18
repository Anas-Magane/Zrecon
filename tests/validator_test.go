package tests

import (
	"testing"

	"github.com/Anas-Magane/zrecon/internal/validator"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    string
	}{
		{"example.com", false, "example.com"},
		{"EXAMPLE.COM", false, "example.com"},
		{"sub.example.com", false, "sub.example.com"},
		{"example.com/", true, ""},
		{"", true, ""},
		{"192.168.1.1", true, ""},
		{"bad domain", true, ""},
		{"example..com", true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := validator.ValidateDomain(tc.input, false)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
				return
			}
			if got.Domain != tc.want {
				t.Errorf("domain: got %q, want %q", got.Domain, tc.want)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		input        string
		allowPrivate bool
		wantErr      bool
	}{
		{"8.8.8.8", false, false},
		{"1.1.1.1", false, false},
		{"192.168.1.1", false, true}, // private, disallowed
		{"192.168.1.1", true, false}, // private, allowed
		{"127.0.0.1", false, true},   // loopback, disallowed
		{"not-an-ip", false, true},
		{"2001:db8::1", false, true}, // IPv6 not supported
		{"", false, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := validator.ValidateIP(tc.input, tc.allowPrivate)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q (allowPrivate=%v)", tc.input, tc.allowPrivate)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		input      string
		wantErr    bool
		wantDomain string
		wantScheme string
	}{
		{"https://example.com", false, "example.com", "https"},
		{"http://example.com", false, "example.com", "http"},
		{"https://example.com/path", false, "example.com", "https"},
		{"example.com", false, "example.com", "https"}, // auto-prepend https
		{"", true, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := validator.ValidateURL(tc.input, false)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
				return
			}
			if got.Domain != tc.wantDomain {
				t.Errorf("domain: got %q, want %q", got.Domain, tc.wantDomain)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("scheme: got %q, want %q", got.Scheme, tc.wantScheme)
			}
		})
	}
}

func TestParseAuto(t *testing.T) {
	tests := []struct {
		input    string
		wantType string
	}{
		{"example.com", "domain"},
		{"https://example.com", "url"},
		{"http://example.com", "url"},
		{"8.8.8.8", "ip"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := validator.ParseAuto(tc.input, true)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.Type != tc.wantType {
				t.Errorf("type: got %q, want %q", got.Type, tc.wantType)
			}
		})
	}
}
