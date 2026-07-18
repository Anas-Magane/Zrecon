package validator

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/Anas-Magane/zrecon/internal/models"
)

var privateRanges = []net.IPNet{
	parseCIDR("10.0.0.0/8"),
	parseCIDR("172.16.0.0/12"),
	parseCIDR("192.168.0.0/16"),
	parseCIDR("127.0.0.0/8"),
	parseCIDR("169.254.0.0/16"),
	parseCIDR("::1/128"),
	parseCIDR("fc00::/7"),
}

func parseCIDR(s string) net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return *n
}

func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateDomain parses and validates a domain target.
func ValidateDomain(raw string, allowPrivate bool) (*models.Target, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}
	if strings.Contains(domain, "/") || strings.Contains(domain, " ") {
		return nil, fmt.Errorf("invalid domain: %q", domain)
	}
	if net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("%q looks like an IP address, use --ip instead", domain)
	}
	// basic label check
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return nil, fmt.Errorf("invalid domain: %q", domain)
		}
	}
	if ip := net.ParseIP(domain); ip != nil {
		if !allowPrivate && isPrivateIP(ip) {
			return nil, fmt.Errorf("private IP not allowed without --allow-private")
		}
	}
	return &models.Target{
		Raw:          raw,
		Type:         "domain",
		Domain:       domain,
		AllowPrivate: allowPrivate,
	}, nil
}

// ValidateIP parses and validates a public IPv4 target.
func ValidateIP(raw string, allowPrivate bool) (*models.Target, error) {
	addr := strings.TrimSpace(raw)
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", addr)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 addresses are supported: %q", addr)
	}
	if !allowPrivate && isPrivateIP(ip) {
		return nil, fmt.Errorf("private IP %q not allowed without --allow-private", addr)
	}
	return &models.Target{
		Raw:          raw,
		Type:         "ip",
		IP:           addr,
		AllowPrivate: allowPrivate,
	}, nil
}

// ValidateURL parses and validates a URL target.
func ValidateURL(raw string, allowPrivate bool) (*models.Target, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("URL missing host: %q", raw)
	}

	port := 0
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	domain := host
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && isPrivateIP(ip) {
			return nil, fmt.Errorf("private IP in URL not allowed without --allow-private")
		}
		domain = ""
	}

	finalURL := strings.TrimRight(raw, "/")

	return &models.Target{
		Raw:    raw,
		Type:   "url",
		URL:    finalURL,
		Domain: domain,
		IP: func() string {
			if domain == "" {
				return host
			}
			return ""
		}(),
		Port:         port,
		Scheme:       u.Scheme,
		AllowPrivate: allowPrivate,
	}, nil
}

// LoadTargetFile reads targets from a file, skipping comments and empty lines.
func LoadTargetFile(path string, allowPrivate bool) ([]*models.Target, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("open file: %w", err)}
	}
	defer f.Close()

	seen := map[string]bool{}
	var targets []*models.Target
	var errs []error

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true

		t, err := ParseAuto(line, allowPrivate)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d %q: %w", lineNum, line, err))
			continue
		}
		targets = append(targets, t)
	}
	return targets, errs
}

// ParseAuto detects the type of a raw target string and validates it.
func ParseAuto(raw string, allowPrivate bool) (*models.Target, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return ValidateURL(raw, allowPrivate)
	}
	if net.ParseIP(raw) != nil {
		return ValidateIP(raw, allowPrivate)
	}
	return ValidateDomain(raw, allowPrivate)
}
