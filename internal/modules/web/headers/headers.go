package headers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type headerDef struct {
	Name string
	Note string
}

var securityHeaders = []headerDef{
	{Name: "Content-Security-Policy", Note: "Prevents XSS and injection attacks"},
	{Name: "Strict-Transport-Security", Note: "Enforces HTTPS connections"},
	{Name: "X-Frame-Options", Note: "Prevents clickjacking"},
	{Name: "X-Content-Type-Options", Note: "Prevents MIME sniffing"},
	{Name: "Referrer-Policy", Note: "Controls referrer information"},
	{Name: "Permissions-Policy", Note: "Controls browser feature access"},
	{Name: "Access-Control-Allow-Origin", Note: "CORS policy"},
}

type Module struct {
	timeout int
}

func New(timeout int) *Module { return &Module{timeout: timeout} }

func (m *Module) Name() string                { return "headers" }
func (m *Module) Description() string         { return "Security header analysis" }
func (m *Module) Category() string            { return "web" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	services := state.Result.HTTPServices
	if len(services) == 0 {
		return nil
	}

	client := buildClient(m.timeout)
	count := 0

	for _, svc := range services {
		if svc.StatusCode == 0 {
			continue
		}

		hdrs := analyzeHeaders(ctx, client, svc.FinalURL)
		for _, h := range hdrs {
			state.Result.SecurityHeaders = append(state.Result.SecurityHeaders, h)
			if h.Status == "missing" {
				logger.Verbose(fmt.Sprintf("Missing header: %s @ %s", h.Name, svc.FinalURL))
			} else {
				count++
			}
		}
	}

	logger.ModuleDone("Security header analysis", fmt.Sprintf("%d headers present", count))
	return nil
}

func analyzeHeaders(ctx context.Context, client *http.Client, url string) []models.SecurityHeader {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", metadata.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var results []models.SecurityHeader
	for _, hd := range securityHeaders {
		val := resp.Header.Get(hd.Name)
		h := models.SecurityHeader{
			URL:  url,
			Name: hd.Name,
		}

		if val == "" {
			h.Status = "missing"
			h.Note = "Manual validation required: " + hd.Note
		} else {
			h.Value = val
			h.Status = "present"
			// Check for known weak values
			if hd.Name == "X-Frame-Options" && strings.ToUpper(val) == "ALLOWALL" {
				h.Status = "potential-hardening-issue"
				h.Note = "ALLOWALL is permissive"
			}
			if hd.Name == "Access-Control-Allow-Origin" && val == "*" {
				h.Status = "potential-hardening-issue"
				h.Note = "Wildcard CORS may expose sensitive data"
			}
			if hd.Name == "Strict-Transport-Security" && !strings.Contains(strings.ToLower(val), "max-age") {
				h.Status = "potential-hardening-issue"
				h.Note = "HSTS missing max-age directive"
			}
		}
		results = append(results, h)
	}
	return results
}

func buildClient(timeoutSec int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: time.Duration(timeoutSec) * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
}
