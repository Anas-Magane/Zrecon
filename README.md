# Zrecon

```
███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
╚══███╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ███╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

       Advanced Reconnaissance & Enumeration Framework
       v1.0.0 · Author: Ziad
```

> **For authorized penetration testing, security research, and bug bounty programs only.**

## Description

Zrecon is a lightweight command-line reconnaissance framework written in Go. It automates the most important passive and active information-gathering tasks used during authorized penetration tests — from DNS enumeration and subdomain discovery to port scanning, service detection, web probing, and TLS analysis — and correlates all results into a unified structured report.

## Features

- **Asset Discovery** — DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA), passive subdomain discovery via Certificate Transparency, subdomain resolution, wildcard DNS detection, and reverse DNS lookup
- **Network Discovery** — Safe TCP connect port scanning with top-20/100 and custom port support, and banner-based service detection
- **Web Discovery** — HTTP/HTTPS probing with title and redirect tracking, technology fingerprinting (Nginx, WordPress, React, Laravel, etc.), security header analysis, and TLS certificate collection
- **Reporting** — TXT, JSON, and standalone offline HTML reports with searchable tables
- **Safety Controls** — Active modules require `--authorized`, private IPs are blocked by default, no exploitation or stealth techniques
- **Concurrency** — Worker pools, rate limiter, context cancellation, race-condition-free

## Architecture

```
CLI (Cobra)
 └── Engine
      ├── Asset Modules:   dns, subdomains, resolve, reverse-dns
      ├── Network Modules: ports, services
      ├── Web Modules:     http, technologies, headers, tls
      └── Output:          txt, json, html
```

## Installation

**Prerequisites:** Go 1.23+

```bash
git clone https://github.com/Anas-Magane/zrecon
cd zrecon
make build
sudo make install
```

Or manually:

```bash
go build -o bin/zrecon .
sudo cp bin/zrecon /usr/local/bin/
```

## Usage

```
Usage:
  zrecon [command] [options]

Commands:
  scan             Run a reconnaissance scan
  modules          Display available modules
  version          Display the current version
  help             Display the help menu

Target Options:
  -d, --domain DOMAIN        Set the target domain
  -u, --url URL              Set the target URL
  -i, --ip IP                Set the target public IP address
  -l, --list FILE            Load targets from a file

Scan Options:
  -m, --modules MODULES      Select comma-separated modules
  -a, --all                  Run all modules
  -p, --passive              Run passive modules only
  -A, --active               Enable active reconnaissance
  -t, --threads NUMBER       Number of concurrent workers
  --ports PORTS              Custom ports or ranges
  --top-ports NUMBER         Scan common ports
  --timeout SECONDS          Request timeout
  --rate-limit NUMBER        Maximum requests per second
  --authorized               Confirm authorization

Output Options:
  -o, --output DIRECTORY     Output directory
  -f, --format FORMAT        txt, json or html
  --silent                   Display findings only
  --no-color                 Disable colors
  -v, --verbose              Verbose logs
  --debug                    Debug logs
```

## Commands

| Command | Description |
|---|---|
| `zrecon scan` | Run a reconnaissance scan |
| `zrecon modules` | List all available modules |
| `zrecon version` | Show version and author info |
| `zrecon help` | Show help |

## Modules

| Name | Category | Mode | Description |
|---|---|---|---|
| dns | asset | passive | Enumerate DNS records |
| subdomains | asset | passive | Discover subdomains via Certificate Transparency |
| resolve | asset | active | Resolve discovered subdomains |
| reverse-dns | asset | passive | PTR lookups for IP targets |
| ports | network | active | Safe TCP connect port scanning |
| services | network | active | Banner-based service detection |
| http | web | active | HTTP/HTTPS probing |
| technologies | web | active | Web technology fingerprinting |
| headers | web | active | Security header analysis |
| tls | web | active | TLS certificate collection |
| report | reporting | local | Generate TXT/JSON/HTML reports |

## Examples

```bash
# Passive-only domain scan
zrecon scan -d example.com --passive

# DNS + subdomain discovery
zrecon scan -d example.com -m dns,subdomains

# Full scan (requires authorization)
zrecon scan -d example.com --all --authorized

# IP scan with port scanning
zrecon scan -i 8.8.8.8 -m ports,services --authorized

# Custom ports
zrecon scan -d example.com --ports 80,443,8080 --authorized

# Multiple targets from file
zrecon scan -l targets.txt --passive

# Silent mode, JSON output only
zrecon scan -d example.com --passive --silent -f json

# URL target
zrecon scan -u https://example.com --authorized
```

## Output Structure

```
results/
└── example.com/
    └── 2026-07-16_15-30-00/
        ├── summary.txt
        ├── results.json
        ├── report.html
        ├── dns.txt
        ├── subdomains.txt
        ├── ips.txt
        ├── ports.txt
        ├── services.txt
        ├── web-services.txt
        └── scan.log
```

## Authorization Warning

Zrecon is intended **only** for:

- Authorized penetration testing
- Assets you own
- Bug bounty programs within scope
- Educational/laboratory environments

**Never scan systems without explicit written permission. Unauthorized use may be illegal.**

Active modules (ports, services, resolve, http, technologies, headers, tls) require the `--authorized` flag.

## Development

```bash
make fmt      # Format code
make vet      # Run go vet
make test     # Run tests
make race     # Run tests with race detector
make build    # Build binary
make clean    # Remove build artifacts
```

## Testing

```bash
go test ./...
go test -race ./...
```

## Configuration

Default config path: `~/.config/zrecon/config.yaml`

See `configs/config.example.yaml` for all options.

## Limitations

- Subdomain discovery uses only public Certificate Transparency (crt.sh) and HackerTarget — no paid API keys required, but coverage may be incomplete
- Port scanning is TCP connect only — no SYN, UDP, or stealth scanning
- Technology detection uses header/HTML signature matching — not a full fingerprinting engine
- No vulnerability scanning, exploitation, or brute force
- IPv6 scanning not supported

## Roadmap (v2)

- Screenshots of web services
- SQLite scan history and diff
- Nuclei integration
- JavaScript secret scanning
- Scan resume support
- Docker container
- CIDR range targeting

## Author

**Ziad**

- GitHub: [https://github.com/Anas-Magane](https://github.com/Anas-Magane)
- LinkedIn: [https://www.linkedin.com/in/Anas-Magane](https://www.linkedin.com/in/Anas-Magane)

## License

MIT — see [LICENSE](LICENSE)
