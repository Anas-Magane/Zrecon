package ports

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
	"golang.org/x/time/rate"
)

// Top ports lists
var top20 = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
}

var top100 = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
	79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
	646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
	2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
	5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
	9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

type Module struct {
	threads   int
	timeout   int
	topPorts  int
	portList  string
	rateLimit int
}

func New(threads, timeout, topPorts, rateLimit int, portList string) *Module {
	return &Module{
		threads:   threads,
		timeout:   timeout,
		topPorts:  topPorts,
		portList:  portList,
		rateLimit: rateLimit,
	}
}

func (m *Module) Name() string                { return "ports" }
func (m *Module) Description() string         { return "TCP port scanning" }
func (m *Module) Category() string            { return "network" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return true }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	targets := buildTargets(target, state)
	if len(targets) == 0 {
		return fmt.Errorf("no hosts to scan")
	}

	portList := m.buildPortList()
	if len(portList) == 0 {
		return fmt.Errorf("no ports to scan")
	}

	logger.Info(fmt.Sprintf("Scanning %d port(s) on %d host(s)", len(portList), len(targets)))

	limiter := rate.NewLimiter(rate.Limit(m.rateLimit), m.rateLimit)
	timeout := time.Duration(m.timeout) * time.Second

	type job struct {
		host string
		ip   string
		port int
	}

	jobs := make(chan job, len(targets)*len(portList))
	for _, t := range targets {
		for _, p := range portList {
			jobs <- job{t[0], t[1], p}
		}
	}
	close(jobs)

	var mu sync.Mutex
	threads := m.threads
	if threads < 1 {
		threads = 20
	}

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

				if err := limiter.Wait(ctx); err != nil {
					return
				}

				start := time.Now()
				addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				elapsed := time.Since(start)
				if err != nil {
					continue
				}
				conn.Close()

				p := models.Port{
					Host:         j.host,
					IP:           j.ip,
					Number:       j.port,
					Protocol:     "tcp",
					State:        "open",
					ResponseTime: elapsed,
				}
				mu.Lock()
				state.Result.Ports = append(state.Result.Ports, p)
				mu.Unlock()
				logger.Finding(fmt.Sprintf("%s:%d/tcp open (%s)", j.host, j.port, elapsed.Round(time.Millisecond)))
			}
		}()
	}
	wg.Wait()

	sort.Slice(state.Result.Ports, func(i, j int) bool {
		return state.Result.Ports[i].Number < state.Result.Ports[j].Number
	})

	logger.ModuleDone("Port scanning", fmt.Sprintf("%d open ports", len(state.Result.Ports)))
	return nil
}

func (m *Module) buildPortList() []int {
	if m.portList != "" {
		return ParsePortSpec(m.portList)
	}
	switch {
	case m.topPorts <= 20:
		return top20
	default:
		return top100
	}
}

// ParsePortSpec parses strings like "22,80,443,8000-8100".
func ParsePortSpec(spec string) []int {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				continue
			}
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo > hi {
				continue
			}
			for p := lo; p <= hi && p <= 65535; p++ {
				seen[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				seen[p] = true
			}
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// buildTargets collects [host, ip] pairs from the target and resolved subdomains.
func buildTargets(target models.Target, state *engine.ScanState) [][2]string {
	var result [][2]string
	seen := map[string]bool{}

	add := func(host, ip string) {
		key := host + ":" + ip
		if !seen[key] {
			seen[key] = true
			result = append(result, [2]string{host, ip})
		}
	}

	if target.IP != "" {
		add(target.IP, target.IP)
	}
	if target.Domain != "" {
		// resolve the root domain
		addrs, err := net.LookupHost(target.Domain)
		if err == nil {
			for _, a := range addrs {
				add(target.Domain, a)
			}
		}
	}
	for _, ip := range state.Result.IPAddresses {
		for _, h := range ip.Hostnames {
			add(h, ip.Address)
		}
		if len(ip.Hostnames) == 0 {
			add(ip.Address, ip.Address)
		}
	}
	return result
}
