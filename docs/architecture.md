# Zrecon Architecture

## Component Overview

```
zrecon/
├── main.go              — Entry point
├── cmd/                 — Cobra CLI commands
│   ├── root.go          — Root command, persistent flags
│   ├── scan.go          — Main scan command
│   ├── modules.go       — Module listing command
│   └── version.go       — Version command
└── internal/            — Core library (not exported)
    ├── metadata/        — Tool constants (name, version, author)
    ├── banner/          — ASCII banner printer
    ├── config/          — Viper YAML config
    ├── logger/          — Colored terminal logger
    ├── validator/       — Target validation and normalization
    ├── models/          — All data structures
    ├── engine/          — Module runner and ScanState
    ├── output/          — TXT and JSON writers, terminal summary
    ├── report/          — HTML report generator
    └── modules/
        ├── asset/       — dns, subdomains, resolve, reversedns
        ├── network/     — ports, services
        └── web/         — http, technologies, headers, tls
```

## Data Flow

```
User Input
    │
    ▼
Target Validation (validator)
    │
    ▼
Engine.Run()
    ├── DNS Module        → ScanResult.DNSRecords
    ├── Subdomains Module → ScanResult.Subdomains
    ├── Resolve Module    → ScanResult.Subdomains (IPs), IPAddresses
    ├── ReverseDNS Module → ScanResult.IPAddresses (PTR)
    ├── Ports Module      → ScanResult.Ports
    ├── Services Module   → ScanResult.Services
    ├── HTTP Module       → ScanResult.HTTPServices
    ├── Technologies Mod  → ScanResult.Technologies
    ├── Headers Module    → ScanResult.SecurityHeaders
    └── TLS Module        → ScanResult.Certificates
         │
         ▼
    Unified ScanResult
         │
         ├── WriteTXT()   → summary.txt, dns.txt, subdomains.txt, ...
         ├── WriteJSON()  → results.json
         └── WriteHTML()  → report.html
```

## Module Interface

```go
type Module interface {
    Name() string
    Description() string
    Category() string
    IsPassive() bool
    RequiresAuthorization() bool
    Run(ctx context.Context, target Target, state *ScanState) error
}
```

## Concurrency

- Port scanner: worker pool (N goroutines) reading from a buffered channel
- Subdomain resolver: worker pool with mutex-protected ScanState writes
- Rate limiter: `golang.org/x/time/rate` token bucket
- Cancellation: `context.Context` passed to all blocking operations
- No goroutine leaks: all workers exit on `ctx.Done()`
