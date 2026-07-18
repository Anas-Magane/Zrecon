# Zrecon Usage Guide

## Quick Start

```bash
# Build
make build

# Install
sudo make install

# Passive scan (no authorization required)
zrecon scan -d example.com --passive

# Active scan (requires authorization)
zrecon scan -d example.com --all --authorized
```

## Target Types

| Flag | Example | Description |
|---|---|---|
| `-d` | `-d example.com` | Domain name |
| `-u` | `-u https://example.com` | URL |
| `-i` | `-i 8.8.8.8` | IPv4 address |
| `-l` | `-l targets.txt` | File with one target per line |

## Module Selection

```bash
# Run specific modules
zrecon scan -d example.com -m dns,subdomains

# Passive modules only
zrecon scan -d example.com --passive

# All modules (requires --authorized for active)
zrecon scan -d example.com --all --authorized
```

## Output Formats

```bash
# Default: all formats
zrecon scan -d example.com --passive

# JSON only
zrecon scan -d example.com --passive -f json

# HTML only
zrecon scan -d example.com --passive -f html

# Custom output directory
zrecon scan -d example.com --passive -o /tmp/scans
```

## Verbosity

```bash
# Normal output
zrecon scan -d example.com --passive

# Verbose (more details)
zrecon scan -d example.com --passive -v

# Debug (diagnostic info)
zrecon scan -d example.com --passive --debug

# Silent (findings only)
zrecon scan -d example.com --passive --silent
```

## Tuning

```bash
# Custom threads and timeout
zrecon scan -d example.com --authorized -t 50 --timeout 5

# Rate limiting
zrecon scan -d example.com --authorized --rate-limit 20

# Custom ports
zrecon scan -i 10.0.0.1 --ports 22,80,443,8080-8090 --authorized --allow-private
```

## Target File Format

Lines beginning with `#` are comments. Empty lines are ignored. Duplicates are removed.

```text
# Production targets
example.com
api.example.com
8.8.8.8
https://staging.example.com
```
