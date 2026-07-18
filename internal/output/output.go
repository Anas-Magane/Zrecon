package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Anas-Magane/zrecon/internal/models"
)

// PrepareOutputDir creates the output directory for a scan.
func PrepareOutputDir(base, target string) (string, error) {
	ts := time.Now().Format("2006-01-02_15-04-05")
	dir := filepath.Join(base, sanitize(target), ts)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	return dir, nil
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", " ", "_", "\\", "_")
	return r.Replace(s)
}

// WriteTXT writes the full TXT report and individual module files.
func WriteTXT(dir string, result *models.ScanResult, warnings []string) error {
	// summary.txt
	summary := buildSummaryText(result, dir, warnings)
	if err := os.WriteFile(filepath.Join(dir, "summary.txt"), []byte(summary), 0644); err != nil {
		return err
	}

	// dns.txt
	var dns strings.Builder
	dns.WriteString("# DNS Records\n\n")
	for _, r := range result.DNSRecords {
		dns.WriteString(fmt.Sprintf("%-8s %-40s %s\n", r.Type, r.Name, r.Value))
	}
	os.WriteFile(filepath.Join(dir, "dns.txt"), []byte(dns.String()), 0644)

	// subdomains.txt
	var subs strings.Builder
	subs.WriteString("# Subdomains\n\n")
	sorted := make([]models.Subdomain, len(result.Subdomains))
	copy(sorted, result.Subdomains)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, s := range sorted {
		resolved := ""
		if s.Resolved {
			resolved = fmt.Sprintf(" → %s", strings.Join(s.IPs, ", "))
		}
		subs.WriteString(fmt.Sprintf("%s%s\n", s.Name, resolved))
	}
	os.WriteFile(filepath.Join(dir, "subdomains.txt"), []byte(subs.String()), 0644)

	// ips.txt
	var ips strings.Builder
	ips.WriteString("# IP Addresses\n\n")
	for _, ip := range result.IPAddresses {
		ptr := ""
		if ip.PTR != "" {
			ptr = fmt.Sprintf(" [%s]", ip.PTR)
		}
		hosts := ""
		if len(ip.Hostnames) > 0 {
			hosts = " (" + strings.Join(ip.Hostnames, ", ") + ")"
		}
		ips.WriteString(fmt.Sprintf("%s%s%s\n", ip.Address, ptr, hosts))
	}
	os.WriteFile(filepath.Join(dir, "ips.txt"), []byte(ips.String()), 0644)

	// ports.txt
	var pts strings.Builder
	pts.WriteString("# Open Ports\n\n")
	for _, p := range result.Ports {
		pts.WriteString(fmt.Sprintf("%s:%d/%s\n", p.Host, p.Number, p.Protocol))
	}
	os.WriteFile(filepath.Join(dir, "ports.txt"), []byte(pts.String()), 0644)

	// services.txt
	var svcs strings.Builder
	svcs.WriteString("# Services\n\n")
	for _, s := range result.Services {
		line := fmt.Sprintf("%s:%d/%s %s", s.Host, s.Port, s.Protocol, s.Name)
		if s.Product != "" {
			line += " " + s.Product
		}
		if s.Version != "" {
			line += "/" + s.Version
		}
		svcs.WriteString(line + "\n")
	}
	os.WriteFile(filepath.Join(dir, "services.txt"), []byte(svcs.String()), 0644)

	// web-services.txt
	var web strings.Builder
	web.WriteString("# Web Services\n\n")
	for _, svc := range result.HTTPServices {
		web.WriteString(fmt.Sprintf("[%d] %s\n", svc.StatusCode, svc.FinalURL))
		if svc.Title != "" {
			web.WriteString(fmt.Sprintf("    Title   : %s\n", svc.Title))
		}
		if svc.Server != "" {
			web.WriteString(fmt.Sprintf("    Server  : %s\n", svc.Server))
		}
	}
	os.WriteFile(filepath.Join(dir, "web-services.txt"), []byte(web.String()), 0644)

	return nil
}

// WriteJSON writes results.json.
func WriteJSON(dir string, result *models.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "results.json"), data, 0644)
}

func buildSummaryText(result *models.ScanResult, dir string, warnings []string) string {
	duration := result.CompletedAt.Sub(result.StartedAt)

	resolved := 0
	for _, s := range result.Subdomains {
		if s.Resolved {
			resolved++
		}
	}

	var sb strings.Builder
	sb.WriteString("# Zrecon Scan Summary\n\n")
	sb.WriteString(fmt.Sprintf("Target   : %s\n", result.Target.Raw))
	sb.WriteString(fmt.Sprintf("Date     : %s\n", result.StartedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Duration : %s\n\n", formatDuration(duration)))
	sb.WriteString(fmt.Sprintf("DNS records           : %d\n", len(result.DNSRecords)))
	sb.WriteString(fmt.Sprintf("Subdomains discovered : %d\n", len(result.Subdomains)))
	sb.WriteString(fmt.Sprintf("Resolved subdomains   : %d\n", resolved))
	sb.WriteString(fmt.Sprintf("Unique IP addresses   : %d\n", len(result.IPAddresses)))
	sb.WriteString(fmt.Sprintf("Open ports            : %d\n", len(result.Ports)))
	sb.WriteString(fmt.Sprintf("Detected services     : %d\n", len(result.Services)))
	sb.WriteString(fmt.Sprintf("Live web services     : %d\n", len(result.HTTPServices)))
	sb.WriteString(fmt.Sprintf("Technologies detected : %d\n", len(result.Technologies)))
	sb.WriteString(fmt.Sprintf("TLS certificates      : %d\n", len(result.Certificates)))
	sb.WriteString(fmt.Sprintf("\nResults: %s\n", dir))

	if len(warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range warnings {
			sb.WriteString("  - " + w + "\n")
		}
	}
	return sb.String()
}

// PrintSummary prints the terminal summary.
func PrintSummary(result *models.ScanResult, dir string, warnings []string) {
	duration := result.CompletedAt.Sub(result.StartedAt)
	resolved := 0
	for _, s := range result.Subdomains {
		if s.Resolved {
			resolved++
		}
	}

	fmt.Println()
	fmt.Printf("Target   : %s\n", result.Target.Raw)
	fmt.Printf("Duration : %s\n\n", formatDuration(duration))
	fmt.Printf("DNS records           : %d\n", len(result.DNSRecords))
	fmt.Printf("Subdomains discovered : %d\n", len(result.Subdomains))
	fmt.Printf("Resolved subdomains   : %d\n", resolved)
	fmt.Printf("Unique IP addresses   : %d\n", len(result.IPAddresses))
	fmt.Printf("Open ports            : %d\n", len(result.Ports))
	fmt.Printf("Detected services     : %d\n", len(result.Services))
	fmt.Printf("Live web services     : %d\n", len(result.HTTPServices))
	fmt.Printf("Technologies detected : %d\n", len(result.Technologies))
	fmt.Printf("TLS certificates      : %d\n\n", len(result.Certificates))
	fmt.Printf("Results  : %s\n", dir)

	if len(warnings) > 0 {
		fmt.Println("\nCompleted with warnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%02dh %02dm %02ds", h, m, s)
	}
	return fmt.Sprintf("%02dm %02ds", m, s)
}
