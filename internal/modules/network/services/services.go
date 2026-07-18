package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
)

type Module struct {
	timeout int
}

func New(timeout int) *Module { return &Module{timeout: timeout} }

func (m *Module) Name() string                { return "services" }
func (m *Module) Description() string         { return "Basic service detection" }
func (m *Module) Category() string            { return "network" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return true }

// Port-to-service mapping
var portServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	openPorts := state.Result.Ports
	if len(openPorts) == 0 {
		return nil
	}

	timeout := time.Duration(m.timeout) * time.Second

	for _, p := range openPorts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		svc := detectService(ctx, p, timeout)
		state.Result.Services = append(state.Result.Services, svc)
		logger.Finding(fmt.Sprintf("%s:%d → %s%s",
			p.Host, p.Number, svc.Name,
			func() string {
				if svc.Banner != "" {
					trimmed := svc.Banner
					if len(trimmed) > 60 {
						trimmed = trimmed[:60] + "..."
					}
					return " [" + trimmed + "]"
				}
				return ""
			}()))
	}

	logger.ModuleDone("Service detection", fmt.Sprintf("%d services identified", len(state.Result.Services)))
	return nil
}

func detectService(ctx context.Context, p models.Port, timeout time.Duration) models.Service {
	svc := models.Service{
		Host:     p.Host,
		IP:       p.IP,
		Port:     p.Number,
		Protocol: "tcp",
	}

	// Port-based name
	if name, ok := portServices[p.Number]; ok {
		svc.Name = name
		svc.Confidence = 0.7
	} else {
		svc.Name = "unknown"
		svc.Confidence = 0.1
	}

	// Banner grab
	addr := net.JoinHostPort(p.IP, fmt.Sprintf("%d", p.Number))
	banner := grabBanner(ctx, addr, p.Number, timeout)
	if banner != "" {
		svc.Banner = banner
		svc.Confidence = 0.9
		enrichFromBanner(&svc, banner)
	}

	return svc
}

func grabBanner(ctx context.Context, addr string, port int, timeout time.Duration) string {
	dialer := &net.Dialer{Timeout: timeout}

	// Try TLS for known HTTPS ports
	if port == 443 || port == 8443 {
		tlsCfg := &tls.Config{InsecureSkipVerify: true}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(timeout / 2))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", addr)
		scanner := bufio.NewScanner(conn)
		if scanner.Scan() {
			return strings.TrimSpace(scanner.Text())
		}
		return ""
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout / 2))

	// Some services (HTTP) need a probe
	switch port {
	case 80, 8080, 8000, 8008, 8888:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", addr)
	case 25, 110, 143, 465, 587, 993, 995:
		// SMTP/POP3/IMAP send a greeting — just read
	case 22:
		// SSH sends version immediately
	default:
		// Generic: just try to read banner
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func enrichFromBanner(svc *models.Service, banner string) {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "openssh"):
		svc.Name = "ssh"
		svc.Product = "OpenSSH"
		parts := strings.Fields(banner)
		for _, p := range parts {
			if strings.HasPrefix(p, "OpenSSH_") {
				svc.Version = strings.TrimPrefix(p, "OpenSSH_")
				break
			}
		}
	case strings.Contains(lower, "apache"):
		svc.Name = "http"
		svc.Product = "Apache httpd"
	case strings.Contains(lower, "nginx"):
		svc.Name = "http"
		svc.Product = "nginx"
	case strings.Contains(lower, "ftp"):
		svc.Name = "ftp"
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "postfix") || strings.Contains(lower, "exim"):
		svc.Name = "smtp"
	case strings.Contains(lower, "ssh"):
		svc.Name = "ssh"
	case strings.Contains(lower, "mysql"):
		svc.Name = "mysql"
		svc.Product = "MySQL"
	case strings.Contains(lower, "redis"):
		svc.Name = "redis"
		svc.Product = "Redis"
	}
}
