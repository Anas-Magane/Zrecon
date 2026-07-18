package resolve

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type Module struct {
	threads int
}

func New(threads int) *Module { return &Module{threads: threads} }

func (m *Module) Name() string                { return "resolve" }
func (m *Module) Description() string         { return "Subdomain resolution" }
func (m *Module) Category() string            { return "asset" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	domain := target.Domain
	if domain == "" {
		return nil
	}

	// First detect wildcard DNS
	wildcardIPs := detectWildcard(ctx, domain)
	if len(wildcardIPs) > 0 {
		logger.Warn(fmt.Sprintf("Wildcard DNS detected for *.%s → %v", domain, wildcardIPs))
	}

	subs := state.Result.Subdomains
	if len(subs) == 0 {
		return nil
	}

	type job struct {
		idx int
		sub models.Subdomain
	}

	jobs := make(chan job, len(subs))
	for i, s := range subs {
		jobs <- job{i, s}
	}
	close(jobs)

	threads := m.threads
	if threads < 1 {
		threads = 10
	}

	var mu sync.Mutex
	ipSet := map[string]bool{}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				sub := j.sub
				addrs, err := net.LookupHost(sub.Name)
				if err != nil {
					logger.Verbose(fmt.Sprintf("Could not resolve %s: %v", sub.Name, err))
					continue
				}

				var ips []string
				for _, a := range addrs {
					ip := net.ParseIP(a)
					if ip == nil {
						continue
					}
					ipStr := ip.String()
					// Check wildcard
					wild := false
					for _, w := range wildcardIPs {
						if w == ipStr {
							wild = true
							break
						}
					}
					if !wild {
						ips = append(ips, ipStr)
					}
				}

				if len(ips) == 0 {
					continue
				}

				sub.IPs = ips
				sub.Resolved = true

				// CNAME lookup
				cname, err := net.LookupCNAME(sub.Name)
				if err == nil {
					cname = strings.TrimSuffix(cname, ".")
					if cname != sub.Name {
						sub.CNAME = cname
					}
				}

				mu.Lock()
				state.Result.Subdomains[j.idx] = sub
				logger.Finding(fmt.Sprintf("%s → %s", sub.Name, strings.Join(ips, ", ")))
				for _, ip := range ips {
					if !ipSet[ip] {
						ipSet[ip] = true
						state.Result.IPAddresses = append(state.Result.IPAddresses, models.IPAddress{
							Address:   ip,
							Hostnames: []string{sub.Name},
						})
					} else {
						for k, existing := range state.Result.IPAddresses {
							if existing.Address == ip {
								state.Result.IPAddresses[k].Hostnames = append(state.Result.IPAddresses[k].Hostnames, sub.Name)
								break
							}
						}
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	resolved := 0
	for _, s := range state.Result.Subdomains {
		if s.Resolved {
			resolved++
		}
	}

	logger.ModuleDone("Subdomain resolution", fmt.Sprintf("%d resolved", resolved))
	return nil
}

func detectWildcard(ctx context.Context, domain string) []string {
	// Query a random non-existent subdomain
	randSub := fmt.Sprintf("zrecon-wildcard-test-12345.%s", domain)
	addrs, err := net.LookupHost(randSub)
	if err != nil {
		return nil
	}
	var ips []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	return ips
}
