package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func (m *Module) Name() string                { return "tls" }
func (m *Module) Description() string         { return "TLS certificate collection" }
func (m *Module) Category() string            { return "web" }
func (m *Module) IsPassive() bool             { return false }
func (m *Module) RequiresAuthorization() bool { return false }

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	type tlsTarget struct {
		host string
		ip   string
		port int
	}

	var targets []tlsTarget
	seen := map[string]bool{}

	add := func(host, ip string, port int) {
		key := fmt.Sprintf("%s:%s:%d", host, ip, port)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, tlsTarget{host, ip, port})
		}
	}

	// From HTTP services (HTTPS only)
	for _, svc := range state.Result.HTTPServices {
		if svc.Scheme == "https" {
			add(svc.OriginalURL, svc.IP, svc.Port)
		}
	}

	// From open ports — known TLS ports
	tlsPorts := map[int]bool{443: true, 8443: true, 465: true, 993: true, 995: true}
	for _, p := range state.Result.Ports {
		if tlsPorts[p.Number] {
			add(p.Host, p.IP, p.Number)
		}
	}

	// Default: try domain:443
	if len(targets) == 0 && target.Domain != "" {
		add(target.Domain, "", 443)
	}

	timeout := time.Duration(m.timeout) * time.Second
	count := 0

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		host := t.host
		// Strip scheme/path if present
		if strings.Contains(host, "://") {
			parts := strings.SplitN(host, "://", 2)
			host = strings.SplitN(parts[1], "/", 2)[0]
			host = strings.SplitN(host, ":", 2)[0]
		}

		addr := net.JoinHostPort(func() string {
			if t.ip != "" {
				return t.ip
			}
			return host
		}(), fmt.Sprintf("%d", t.port))

		cert, err := collectCert(ctx, addr, host, timeout)
		if err != nil {
			logger.Verbose(fmt.Sprintf("TLS failed for %s: %v", addr, err))
			continue
		}

		cert.Host = host
		state.Result.Certificates = append(state.Result.Certificates, *cert)

		expStatus := ""
		if cert.Expired {
			expStatus = " [EXPIRED]"
		} else if cert.ExpiringSoon {
			expStatus = " [expiring soon]"
		}
		logger.Finding(fmt.Sprintf("TLS: %s [%s] valid until %s%s",
			host, cert.Issuer, cert.ValidUntil.Format("2006-01-02"), expStatus))
		count++
	}

	logger.ModuleDone("TLS collection", fmt.Sprintf("%d certificates", count))
	return nil
}

func collectCert(ctx context.Context, addr, host string, timeout time.Duration) (*models.Certificate, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	leaf := state.PeerCertificates[0]
	now := time.Now()
	expired := now.After(leaf.NotAfter)
	expiringSoon := !expired && leaf.NotAfter.Sub(now) < 30*24*time.Hour

	// Check self-signed: issuer == subject
	selfSigned := leaf.Issuer.String() == leaf.Subject.String()

	// Determine if issuer is the leaf or a different cert
	if len(state.PeerCertificates) > 1 {
		parent := state.PeerCertificates[len(state.PeerCertificates)-1]
		selfSigned = parent.Issuer.String() == parent.Subject.String()
	}

	tlsVer := tlsVersionString(state.Version)

	return &models.Certificate{
		Subject:      leaf.Subject.String(),
		Issuer:       issuerOrg(leaf),
		ValidFrom:    leaf.NotBefore,
		ValidUntil:   leaf.NotAfter,
		DNSNames:     leaf.DNSNames,
		Expired:      expired,
		ExpiringSoon: expiringSoon,
		SelfSigned:   selfSigned,
		TLSVersion:   tlsVer,
	}, nil
}

func issuerOrg(cert *x509.Certificate) string {
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
