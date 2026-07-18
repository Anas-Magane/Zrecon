package technologies

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type techSignature struct {
	name     string
	category string
	checks   []check
}

type check struct {
	source   string // header, cookie, body, meta, script
	key      string
	pattern  string
	evidence string
}

var signatures = []techSignature{
	{name: "Nginx", category: "Web Server", checks: []check{
		{source: "header", key: "Server", pattern: "nginx", evidence: "Server: nginx"},
	}},
	{name: "Apache", category: "Web Server", checks: []check{
		{source: "header", key: "Server", pattern: "apache", evidence: "Server: Apache"},
	}},
	{name: "IIS", category: "Web Server", checks: []check{
		{source: "header", key: "Server", pattern: "microsoft-iis", evidence: "Server: Microsoft-IIS"},
	}},
	{name: "Cloudflare", category: "CDN", checks: []check{
		{source: "header", key: "Server", pattern: "cloudflare", evidence: "Server: cloudflare"},
		{source: "header", key: "CF-RAY", pattern: "", evidence: "CF-RAY header"},
	}},
	{name: "WordPress", category: "CMS", checks: []check{
		{source: "body", key: "", pattern: "wp-content", evidence: "wp-content in HTML"},
		{source: "body", key: "", pattern: "wp-includes", evidence: "wp-includes in HTML"},
		{source: "meta", key: "generator", pattern: "wordpress", evidence: "meta generator: WordPress"},
	}},
	{name: "Drupal", category: "CMS", checks: []check{
		{source: "header", key: "X-Generator", pattern: "drupal", evidence: "X-Generator: Drupal"},
		{source: "body", key: "", pattern: "drupal.js", evidence: "drupal.js in HTML"},
		{source: "meta", key: "generator", pattern: "drupal", evidence: "meta generator: Drupal"},
	}},
	{name: "Joomla", category: "CMS", checks: []check{
		{source: "meta", key: "generator", pattern: "joomla", evidence: "meta generator: Joomla"},
		{source: "body", key: "", pattern: "/media/jui/", evidence: "/media/jui/ in HTML"},
	}},
	{name: "Django", category: "Framework", checks: []check{
		{source: "header", key: "X-Frame-Options", pattern: "sameorigin", evidence: "Django default X-Frame-Options"},
		{source: "cookie", key: "csrftoken", pattern: "", evidence: "CSRF token cookie"},
	}},
	{name: "Laravel", category: "Framework", checks: []check{
		{source: "cookie", key: "laravel_session", pattern: "", evidence: "laravel_session cookie"},
		{source: "header", key: "X-Powered-By", pattern: "php", evidence: "X-Powered-By: PHP"},
	}},
	{name: "ASP.NET", category: "Framework", checks: []check{
		{source: "header", key: "X-Powered-By", pattern: "asp.net", evidence: "X-Powered-By: ASP.NET"},
		{source: "header", key: "X-AspNet-Version", pattern: "", evidence: "X-AspNet-Version header"},
	}},
	{name: "Spring", category: "Framework", checks: []check{
		{source: "header", key: "X-Application-Context", pattern: "", evidence: "X-Application-Context header"},
	}},
	{name: "Flask", category: "Framework", checks: []check{
		{source: "header", key: "Server", pattern: "werkzeug", evidence: "Server: Werkzeug"},
	}},
	{name: "React", category: "JavaScript", checks: []check{
		{source: "body", key: "", pattern: "react.js", evidence: "react.js in HTML"},
		{source: "body", key: "", pattern: "react.min.js", evidence: "react.min.js in HTML"},
		{source: "body", key: "", pattern: "__REACT", evidence: "__REACT in HTML"},
	}},
	{name: "Vue.js", category: "JavaScript", checks: []check{
		{source: "body", key: "", pattern: "vue.js", evidence: "vue.js in HTML"},
		{source: "body", key: "", pattern: "vue.min.js", evidence: "vue.min.js in HTML"},
	}},
	{name: "Angular", category: "JavaScript", checks: []check{
		{source: "body", key: "", pattern: "ng-version", evidence: "ng-version in HTML"},
		{source: "body", key: "", pattern: "angular.min.js", evidence: "angular.min.js in HTML"},
	}},
	{name: "Next.js", category: "JavaScript Framework", checks: []check{
		{source: "header", key: "X-Powered-By", pattern: "next.js", evidence: "X-Powered-By: Next.js"},
		{source: "body", key: "", pattern: "__NEXT_DATA__", evidence: "__NEXT_DATA__ in HTML"},
	}},
	{name: "PHP", category: "Language", checks: []check{
		{source: "header", key: "X-Powered-By", pattern: "php", evidence: "X-Powered-By: PHP"},
	}},
}

type Module struct {
	timeout int
}

func New(timeout int) *Module { return &Module{timeout: timeout} }

func (m *Module) Name() string                { return "technologies" }
func (m *Module) Description() string         { return "Web technology detection" }
func (m *Module) Category() string            { return "web" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	services := state.Result.HTTPServices
	if len(services) == 0 {
		return nil
	}

	client := buildClient(m.timeout)
	seen := map[string]bool{}
	count := 0

	for _, svc := range services {
		if svc.StatusCode == 0 {
			continue
		}

		techs := detectTechs(ctx, client, svc)
		for _, t := range techs {
			key := svc.FinalURL + "|" + t.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			state.Result.Technologies = append(state.Result.Technologies, t)
			logger.Finding(fmt.Sprintf("Technology: %s [%s] @ %s", t.Name, t.Category, svc.FinalURL))
			count++
		}
	}

	logger.ModuleDone("Technology detection", fmt.Sprintf("%d technologies detected", count))
	return nil
}

func detectTechs(ctx context.Context, client *http.Client, svc models.HTTPService) []models.Technology {
	// Fetch the page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc.FinalURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", metadata.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := strings.ToLower(string(body))

	// Parse HTML for meta and scripts
	var metaGenerators []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err == nil {
		doc.Find("meta[name='generator']").Each(func(_ int, s *goquery.Selection) {
			if v, ok := s.Attr("content"); ok {
				metaGenerators = append(metaGenerators, strings.ToLower(v))
			}
		})
	}

	// Collect cookies
	cookieNames := map[string]bool{}
	for _, c := range resp.Cookies() {
		cookieNames[strings.ToLower(c.Name)] = true
	}

	var found []models.Technology
	for _, sig := range signatures {
		for _, c := range sig.checks {
			matched := false
			evidence := c.evidence
			switch c.source {
			case "header":
				val := strings.ToLower(resp.Header.Get(c.key))
				if c.pattern == "" {
					matched = val != ""
				} else {
					matched = strings.Contains(val, c.pattern)
				}
			case "cookie":
				if c.pattern == "" {
					matched = cookieNames[strings.ToLower(c.key)]
				}
			case "body":
				matched = strings.Contains(bodyStr, c.pattern)
			case "meta":
				for _, mg := range metaGenerators {
					if strings.Contains(mg, c.pattern) {
						matched = true
						evidence = "meta generator: " + mg
						break
					}
				}
			}
			if matched {
				found = append(found, models.Technology{
					URL:        svc.FinalURL,
					Name:       sig.name,
					Category:   sig.category,
					Evidence:   evidence,
					Confidence: "high",
				})
				break
			}
		}
	}
	return found
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
