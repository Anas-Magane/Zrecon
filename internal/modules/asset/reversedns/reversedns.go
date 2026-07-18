package reversedns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string                { return "reverse-dns" }
func (m *Module) Description() string         { return "Reverse DNS lookup" }
func (m *Module) Category() string            { return "asset" }
func (m *Module) IsPassive() bool             { return true }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	var ips []string

	if target.IP != "" {
		ips = append(ips, target.IP)
	}
	for _, ip := range state.Result.IPAddresses {
		ips = append(ips, ip.Address)
	}

	if len(ips) == 0 {
		return nil
	}

	seen := map[string]bool{}
	count := 0
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ptrs, err := net.LookupAddr(ip)
		if err != nil {
			logger.Verbose(fmt.Sprintf("PTR lookup failed for %s: %v", ip, err))
			continue
		}

		for _, ptr := range ptrs {
			ptr = strings.TrimSuffix(ptr, ".")
			logger.Finding(fmt.Sprintf("PTR: %s → %s", ip, ptr))

			// Update IPAddress record
			for k, existing := range state.Result.IPAddresses {
				if existing.Address == ip {
					state.Result.IPAddresses[k].PTR = ptr
					break
				}
			}

			// If target was IP, add a new IPAddress entry
			if target.IP == ip {
				found := false
				for _, existing := range state.Result.IPAddresses {
					if existing.Address == ip {
						found = true
						break
					}
				}
				if !found {
					state.Result.IPAddresses = append(state.Result.IPAddresses, models.IPAddress{
						Address: ip,
						PTR:     ptr,
					})
				}
			}
			count++
		}
	}

	logger.ModuleDone("Reverse DNS", fmt.Sprintf("%d PTR records", count))
	return nil
}
