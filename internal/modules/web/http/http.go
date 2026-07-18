package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type Module struct {
	threads int
	timeout int
}

func New(threads, timeout int) *Module {
	return &Module{threads: threads, timeout: timeout}
}

func (m *Module) Name() string                { return "http" }
func (m *Module) Description() string         { return "HTTP/HTTPS probing" }
func (m *Module) Category() string            { return "web" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return false }

var httpPorts = map[int][]string{
	80:   {"http"},
	443:  {"https"},
	8080: {"http", "https"},
	8443: {"https"},
	8000: {"http"},
	8008: {"http"},
	8888: {"http"},
	8181: {"http"},
	9000: {"http"},
	9001: {"http"},
}

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	type probe struct {
		host   string
		ip     string
		port   int
		scheme string
	}

	var probes []probe
	seen := map[string]bool{}

	addProbe := func(host, ip string, port int, scheme string) {
		key := fmt.Sprintf("%s://%s:%d", scheme, host, port)
		if !seen[key] {
			seen[key] = true
			probes = append(probes, probe{host, ip, port, scheme})
		}
	}

	// From scan target
	if target.URL != "" {
		scheme := target.Scheme
		if scheme == "" {
			scheme = "https"
		}
		host := target.Domain
		if host == "" {
			host = target.IP
		}
		port := target.Port
		if port == 0 {
			if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		addProbe(host, "", port, scheme)
	}

	// From open ports
	for _, p := range state.Result.Ports {
		schemes, ok := httpPorts[p.Number]
		if !ok {
			// Check service name
			for _, svc := range state.Result.Services {
				if svc.Port == p.Number && (svc.Name == "http" || svc.Name == "https" ||
					strings.Contains(svc.Name, "http")) {
					if p.Number == 443 || p.Number == 8443 {
						schemes = []string{"https"}
					} else {
						schemes = []string{"http"}
					}
					break
				}
			}
		}
		if len(schemes) == 0 {
			continue
		}
		for _, scheme := range schemes {
			addProbe(p.Host, p.IP, p.Number, scheme)
		}
	}

	// Default: probe domain on 80 and 443 if no open ports found
	if len(probes) == 0 && target.Domain != "" {
		addProbe(target.Domain, "", 80, "http")
		addProbe(target.Domain, "", 443, "https")
	}

	if len(probes) == 0 {
		return nil
	}

	client := buildClient(m.timeout)
	jobCh := make(chan probe, len(probes))
	for _, p := range probes {
		jobCh <- p
	}
	close(jobCh)

	var mu sync.Mutex
	threads := m.threads
	if threads < 1 {
		threads = 10
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				url := fmt.Sprintf("%s://%s:%d", p.scheme, p.host, p.port)
				result := probeURL(ctx, client, url, p.ip, p.port, p.scheme)
				if result == nil {
					continue
				}

				mu.Lock()
				state.Result.HTTPServices = append(state.Result.HTTPServices, *result)
				mu.Unlock()

				techs := fmt.Sprintf("")
				if result.Server != "" {
					techs = result.Server
				}
				logger.Finding(fmt.Sprintf("%s [%d] [%s] [%s]",
					result.FinalURL, result.StatusCode, result.Title, techs))
			}
		}()
	}
	wg.Wait()

	logger.ModuleDone("HTTP probing", fmt.Sprintf("%d live services", len(state.Result.HTTPServices)))
	return nil
}

func buildClient(timeoutSec int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: time.Duration(timeoutSec) * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   time.Duration(timeoutSec) * time.Second,
		ResponseHeaderTimeout: time.Duration(timeoutSec) * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func probeURL(ctx context.Context, client *http.Client, rawURL, ip string, port int, scheme string) *models.HTTPService {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", metadata.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	// Read body for title extraction (limit to 512KB)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	title := extractTitle(body)
	finalURL := resp.Request.URL.String()

	resolvedIP := ip
	if resolvedIP == "" {
		host := resp.Request.URL.Hostname()
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			resolvedIP = addrs[0]
		}
	}

	svc := &models.HTTPService{
		OriginalURL:   rawURL,
		FinalURL:      finalURL,
		StatusCode:    resp.StatusCode,
		Title:         title,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		ResponseTime:  elapsed,
		Server:        resp.Header.Get("Server"),
		PoweredBy:     resp.Header.Get("X-Powered-By"),
		IP:            resolvedIP,
		Port:          port,
		Scheme:        scheme,
	}

	return svc
}

func extractTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}
	title := strings.TrimSpace(doc.Find("title").First().Text())
	if len(title) > 100 {
		title = title[:100]
	}
	return title
}
