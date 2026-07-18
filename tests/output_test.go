package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Anas-Magane/zrecon/internal/models"
	"github.com/Anas-Magane/zrecon/internal/output"
	"github.com/Anas-Magane/zrecon/internal/report"
)

func buildTestResult() *models.ScanResult {
	now := time.Now()
	return &models.ScanResult{
		Target: models.Target{Raw: "test.example.com", Type: "domain", Domain: "test.example.com"},
		DNSRecords: []models.DNSRecord{
			{Name: "test.example.com", Type: "A", Value: "1.2.3.4", TTL: 300},
		},
		Subdomains: []models.Subdomain{
			{Name: "api.test.example.com", Sources: []string{"crt.sh"}, Resolved: true, IPs: []string{"1.2.3.5"}},
		},
		IPAddresses: []models.IPAddress{
			{Address: "1.2.3.4", Hostnames: []string{"test.example.com"}},
		},
		Ports: []models.Port{
			{Host: "test.example.com", IP: "1.2.3.4", Number: 443, Protocol: "tcp", State: "open"},
		},
		HTTPServices: []models.HTTPService{
			{OriginalURL: "https://test.example.com", FinalURL: "https://test.example.com", StatusCode: 200, Title: "Test", Scheme: "https"},
		},
		Certificates: []models.Certificate{
			{Host: "test.example.com", Subject: "CN=test.example.com", Issuer: "Let's Encrypt",
				ValidFrom: now.Add(-30 * 24 * time.Hour), ValidUntil: now.Add(60 * 24 * time.Hour), TLSVersion: "TLS 1.3"},
		},
		StartedAt:   now.Add(-2 * time.Minute),
		CompletedAt: now,
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	result := buildTestResult()
	if err := output.WriteJSON(dir, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatalf("could not read results.json: %v", err)
	}
	var parsed models.ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("could not parse results.json: %v", err)
	}
	if parsed.Target.Domain != "test.example.com" {
		t.Errorf("unexpected domain: %s", parsed.Target.Domain)
	}
	if len(parsed.DNSRecords) != 1 {
		t.Errorf("expected 1 DNS record, got %d", len(parsed.DNSRecords))
	}
}

func TestWriteTXT(t *testing.T) {
	dir := t.TempDir()
	result := buildTestResult()
	if err := output.WriteTXT(dir, result, nil); err != nil {
		t.Fatalf("WriteTXT failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "summary.txt")); err != nil {
		t.Error("summary.txt not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "dns.txt")); err != nil {
		t.Error("dns.txt not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "subdomains.txt")); err != nil {
		t.Error("subdomains.txt not created")
	}
}

func TestWriteHTML(t *testing.T) {
	dir := t.TempDir()
	result := buildTestResult()
	if err := report.WriteHTML(dir, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("could not read report.html: %v", err)
	}
	if len(data) < 1000 {
		t.Errorf("HTML report seems too short: %d bytes", len(data))
	}
	if !containsStr(string(data), "test.example.com") {
		t.Error("HTML report missing target domain")
	}
	if !containsStr(string(data), "Zrecon") {
		t.Error("HTML report missing tool name")
	}
}

func TestPrepareOutputDir(t *testing.T) {
	base := t.TempDir()
	dir, err := output.PrepareOutputDir(base, "example.com")
	if err != nil {
		t.Fatalf("PrepareOutputDir failed: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("output dir not created: %v", err)
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
