package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
	"github.com/miekg/dns"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string                { return "dns" }
func (m *Module) Description() string         { return "DNS enumeration" }
func (m *Module) Category() string            { return "asset" }
func (m *Module) IsPassive() bool             { return true }
func (m *Module) RequiresAuthorization() bool { return false }

var recordTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeNS,
	dns.TypeTXT,
	dns.TypeSOA,
	dns.TypeCAA,
}

func (m *Module) Run(ctx context.Context, target models.Target, state *engine.ScanState) error {
	domain := target.Domain
	if domain == "" && target.IP != "" {
		// Reverse DNS
		ptr, err := net.LookupAddr(target.IP)
		if err == nil {
			for _, p := range ptr {
				r := models.DNSRecord{Name: target.IP, Type: "PTR", Value: p}
				state.Result.DNSRecords = append(state.Result.DNSRecords, r)
				logger.Finding(fmt.Sprintf("PTR: %s → %s", target.IP, p))
			}
		}
		return nil
	}

	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	c := new(dns.Client)

	for _, qtype := range recordTypes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		typeName := dns.TypeToString[qtype]
		records, err := query(ctx, c, resolvers, domain, qtype)
		if err != nil {
			logger.Verbose(fmt.Sprintf("DNS %s query failed: %v", typeName, err))
			continue
		}
		for _, rec := range records {
			state.Result.DNSRecords = append(state.Result.DNSRecords, rec)
			logger.Finding(fmt.Sprintf("%s: %s → %s", rec.Type, rec.Name, rec.Value))
		}
	}

	count := len(state.Result.DNSRecords)
	logger.ModuleDone("DNS enumeration", fmt.Sprintf("%d records", count))
	return nil
}

func query(ctx context.Context, c *dns.Client, resolvers []string, domain string, qtype uint16) ([]models.DNSRecord, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, resolver := range resolvers {
		resp, _, err := c.ExchangeContext(ctx, msg, resolver)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			continue
		}
		return parseAnswers(resp.Answer), nil
	}
	return nil, lastErr
}

func parseAnswers(answers []dns.RR) []models.DNSRecord {
	var records []models.DNSRecord
	for _, rr := range answers {
		hdr := rr.Header()
		typeName := dns.TypeToString[hdr.Rrtype]
		name := strings.TrimSuffix(hdr.Name, ".")
		value := ""

		switch v := rr.(type) {
		case *dns.A:
			value = v.A.String()
		case *dns.AAAA:
			value = v.AAAA.String()
		case *dns.CNAME:
			value = strings.TrimSuffix(v.Target, ".")
		case *dns.MX:
			value = fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
		case *dns.NS:
			value = strings.TrimSuffix(v.Ns, ".")
		case *dns.TXT:
			value = strings.Join(v.Txt, " ")
		case *dns.SOA:
			value = fmt.Sprintf("%s %s %d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial)
		case *dns.CAA:
			value = fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
		default:
			value = rr.String()
		}

		if value != "" {
			records = append(records, models.DNSRecord{
				Name:  name,
				Type:  typeName,
				Value: value,
				TTL:   hdr.Ttl,
			})
		}
	}
	return records
}
