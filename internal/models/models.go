package models

import "time"

// Target represents the scan target.
type Target struct {
	Raw          string `json:"raw"`
	Type         string `json:"type"` // domain, ip, url
	Domain       string `json:"domain,omitempty"`
	IP           string `json:"ip,omitempty"`
	URL          string `json:"url,omitempty"`
	Port         int    `json:"port,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	AllowPrivate bool   `json:"allow_private"`
}

// DNSRecord holds a single DNS record.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	Name     string   `json:"name"`
	Sources  []string `json:"sources"`
	Wildcard bool     `json:"wildcard"`
	IPs      []string `json:"ips,omitempty"`
	CNAME    string   `json:"cname,omitempty"`
	Resolved bool     `json:"resolved"`
}

// IPAddress is a unique IP found during the scan.
type IPAddress struct {
	Address   string   `json:"address"`
	Hostnames []string `json:"hostnames,omitempty"`
	PTR       string   `json:"ptr,omitempty"`
}

// Port represents an open port found during scanning.
type Port struct {
	Host         string        `json:"host"`
	IP           string        `json:"ip"`
	Number       int           `json:"number"`
	Protocol     string        `json:"protocol"`
	State        string        `json:"state"`
	ResponseTime time.Duration `json:"response_time_ms"`
}

// Service represents a detected service on a port.
type Service struct {
	Host       string  `json:"host"`
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Name       string  `json:"name"`
	Product    string  `json:"product,omitempty"`
	Version    string  `json:"version,omitempty"`
	Banner     string  `json:"banner,omitempty"`
	Confidence float64 `json:"confidence"`
}

// HTTPService holds the result of HTTP probing.
type HTTPService struct {
	OriginalURL   string        `json:"original_url"`
	FinalURL      string        `json:"final_url"`
	StatusCode    int           `json:"status_code"`
	Title         string        `json:"title"`
	ContentType   string        `json:"content_type"`
	ContentLength int64         `json:"content_length"`
	ResponseTime  time.Duration `json:"response_time_ms"`
	RedirectChain []string      `json:"redirect_chain,omitempty"`
	Server        string        `json:"server,omitempty"`
	PoweredBy     string        `json:"powered_by,omitempty"`
	IP            string        `json:"ip"`
	Port          int           `json:"port"`
	Scheme        string        `json:"scheme"`
}

// Technology represents a detected web technology.
type Technology struct {
	URL        string `json:"url"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"` // high, medium, low
}

// SecurityHeader represents a single security header check.
type SecurityHeader struct {
	URL    string `json:"url"`
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Status string `json:"status"` // present, missing, potential-hardening-issue
	Note   string `json:"note,omitempty"`
}

// Certificate holds TLS certificate information.
type Certificate struct {
	Host         string    `json:"host"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidUntil   time.Time `json:"valid_until"`
	DNSNames     []string  `json:"dns_names"`
	Expired      bool      `json:"expired"`
	ExpiringSoon bool      `json:"expiring_soon"`
	SelfSigned   bool      `json:"self_signed"`
	TLSVersion   string    `json:"tls_version"`
}

// ModuleResult stores the outcome of a single module execution.
type ModuleResult struct {
	Module    string        `json:"module"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration_ms"`
	FindCount int           `json:"find_count"`
}

// ScanSummary is the high-level summary printed at the end.
type ScanSummary struct {
	Target             string   `json:"target"`
	Duration           string   `json:"duration"`
	DNSRecords         int      `json:"dns_records"`
	Subdomains         int      `json:"subdomains"`
	ResolvedSubdomains int      `json:"resolved_subdomains"`
	UniqueIPs          int      `json:"unique_ips"`
	OpenPorts          int      `json:"open_ports"`
	Services           int      `json:"services"`
	LiveWebServices    int      `json:"live_web_services"`
	Technologies       int      `json:"technologies"`
	TLSCertificates    int      `json:"tls_certificates"`
	OutputDir          string   `json:"output_dir"`
	Warnings           []string `json:"warnings,omitempty"`
}

// ScanResult is the unified top-level scan result model.
type ScanResult struct {
	Target          Target           `json:"target"`
	DNSRecords      []DNSRecord      `json:"dns_records"`
	Subdomains      []Subdomain      `json:"subdomains"`
	IPAddresses     []IPAddress      `json:"ip_addresses"`
	Ports           []Port           `json:"ports"`
	Services        []Service        `json:"services"`
	HTTPServices    []HTTPService    `json:"http_services"`
	Technologies    []Technology     `json:"technologies"`
	SecurityHeaders []SecurityHeader `json:"security_headers"`
	Certificates    []Certificate    `json:"certificates"`
	ModuleResults   []ModuleResult   `json:"module_results"`
	StartedAt       time.Time        `json:"started_at"`
	CompletedAt     time.Time        `json:"completed_at"`
}

// ScanConfig holds runtime configuration for a scan.
type ScanConfig struct {
	Modules      []string
	Passive      bool
	Active       bool
	Authorized   bool
	Threads      int
	Ports        string
	TopPorts     int
	Timeout      int
	RateLimit    int
	OutputDir    string
	Formats      []string
	Verbose      bool
	Debug        bool
	Silent       bool
	AllowPrivate bool
}
