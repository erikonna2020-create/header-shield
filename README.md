# header-shield

CLI tool in Python (standard library only) to inspect HTTP/HTTPS redirect chains, audit security headers, detect banner/disclosure headers, score posture (`0–100`, grades `A–F`), and export structured JSON reports.

## Features

- Follows and records HTTP redirect chains (`301`, `302`, `307`, `308`, etc.) up to a safe hop limit.
- Evaluates core security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Highlights potential banner/information disclosure headers (`Server`, `X-Powered-By`, `Via`).
- Outputs clean terminal summaries and machine-readable JSON (`--json` / `--output`).

## Requirements

- Python 3.8+ (no third-party packages required).

## Usage

```bash
python3 audit.py example.com
python3 audit.py [https://example.com](https://example.com) --output examples/sample_report.json
python3 audit.py example.com --json
Example Output
See examples/sample_report.json for a sample JSON report.
Disclaimer
Use only on targets you own or have explicit authorization to test.
