package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type Module struct {
	client *http.Client
}

func New(timeout int) *Module {
	return &Module{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (m *Module) Name() string                { return "subdomains" }
func (m *Module) Description() string         { return "Passive subdomain discovery" }
func (m *Module) Category() string            { return "asset" }
func (m *Module) IsPassive() bool             { return true }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	domain := target.Domain
	if domain == "" {
		return nil
	}

	seen := map[string]bool{}
	var found []models.Subdomain

	// crt.sh Certificate Transparency
	ctSubs, err := m.queryCRTSH(ctx, domain)
	if err != nil {
		logger.Verbose(fmt.Sprintf("crt.sh query failed: %v", err))
	}
	for _, sub := range ctSubs {
		sub = normalize(sub, domain)
		if sub == "" || seen[sub] {
			continue
		}
		seen[sub] = true
		found = append(found, models.Subdomain{
			Name:    sub,
			Sources: []string{"crt.sh"},
		})
		logger.Finding(sub)
	}

	// hackertarget
	htSubs, err := m.queryHackerTarget(ctx, domain)
	if err != nil {
		logger.Verbose(fmt.Sprintf("hackertarget query failed: %v", err))
	}
	for _, sub := range htSubs {
		sub = normalize(sub, domain)
		if sub == "" || seen[sub] {
			continue
		}
		seen[sub] = true
		found = append(found, models.Subdomain{
			Name:    sub,
			Sources: []string{"hackertarget"},
		})
		logger.Finding(sub)
	}

	state.Result.Subdomains = append(state.Result.Subdomains, found...)
	logger.ModuleDone("Subdomain discovery", fmt.Sprintf("%d unique results", len(found)))
	return nil
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func (m *Module) queryCRTSH(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", metadata.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var subs []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

func (m *Module) queryHackerTarget(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", metadata.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			sub := strings.ToLower(strings.TrimSpace(parts[0]))
			if sub != "" {
				subs = append(subs, sub)
			}
		}
	}
	return subs, nil
}

// normalize cleans a subdomain name: strips wildcards, validates it belongs to domain.
func normalize(name, domain string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// Strip wildcard prefix
	for strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if name == domain {
		return ""
	}
	if !strings.HasSuffix(name, "."+domain) {
		return ""
	}
	return name
}
