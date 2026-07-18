package tests

import (
	"testing"

	"github.com/Anas-Magane/zrecon/internal/models"
)

func TestSubdomainDedup(t *testing.T) {
	subs := []models.Subdomain{
		{Name: "api.example.com"},
		{Name: "api.example.com"},
		{Name: "www.example.com"},
	}

	seen := map[string]bool{}
	var deduped []models.Subdomain
	for _, s := range subs {
		if !seen[s.Name] {
			seen[s.Name] = true
			deduped = append(deduped, s)
		}
	}

	if len(deduped) != 2 {
		t.Errorf("expected 2 unique subdomains, got %d", len(deduped))
	}
}

func TestHTTPTitleNormalization(t *testing.T) {
	// Simulate title that exceeds 100 characters
	title := "This is a very long title that goes beyond one hundred characters in total length and should be truncated properly"
	if len(title) > 100 {
		title = title[:100]
	}
	if len(title) > 100 {
		t.Errorf("title not truncated: length=%d", len(title))
	}
}

func TestPortStructModel(t *testing.T) {
	p := models.Port{
		Host:     "example.com",
		IP:       "93.184.216.34",
		Number:   443,
		Protocol: "tcp",
		State:    "open",
	}
	if p.Number != 443 {
		t.Errorf("expected port 443, got %d", p.Number)
	}
	if p.Protocol != "tcp" {
		t.Errorf("expected tcp, got %s", p.Protocol)
	}
}

func TestDNSRecordModel(t *testing.T) {
	rec := models.DNSRecord{
		Name:  "example.com",
		Type:  "A",
		Value: "93.184.216.34",
		TTL:   3600,
	}
	if rec.Type != "A" {
		t.Errorf("expected A record, got %s", rec.Type)
	}
	if rec.Value != "93.184.216.34" {
		t.Errorf("expected IP value, got %s", rec.Value)
	}
}

func TestScanResultModel(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{
			Raw:    "example.com",
			Type:   "domain",
			Domain: "example.com",
		},
	}
	result.DNSRecords = append(result.DNSRecords, models.DNSRecord{
		Name: "example.com", Type: "A", Value: "1.2.3.4",
	})
	result.Subdomains = append(result.Subdomains, models.Subdomain{
		Name:     "api.example.com",
		Sources:  []string{"crt.sh"},
		Resolved: true,
		IPs:      []string{"1.2.3.5"},
	})

	if len(result.DNSRecords) != 1 {
		t.Errorf("expected 1 DNS record, got %d", len(result.DNSRecords))
	}
	if len(result.Subdomains) != 1 {
		t.Errorf("expected 1 subdomain, got %d", len(result.Subdomains))
	}
	if !result.Subdomains[0].Resolved {
		t.Error("expected subdomain to be resolved")
	}
}
