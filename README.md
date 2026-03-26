# subenum

Passive subdomain enumeration CLI for Bug Bounty reconnaissance.

`subenum` reads a list of root domains, queries multiple passive sources in
parallel, deduplicates the results, validates them via DNS, probes for live
HTTP services, fingerprints technologies, detects WAFs, identifies third-party
services, detects potential CNAME takeovers, flags interesting high-value
targets, scans open ports, and exports everything to structured output files
ready for your Bug Bounty workflow.

## Features

- **10 passive sources**: crt.sh, VirusTotal, urlscan.io, AlienVault OTX,
  HackerTarget, Wayback Machine, RapidDNS, Anubis DB, subfinder (external
  binary) and amass (external binary).
- **6 free sources** that need no API key (crt.sh, AlienVault, HackerTarget,
  Wayback, RapidDNS, Anubis).
- Parallel async execution for speed.
- DNS validation (A / AAAA / CNAME) with configurable resolvers.
- Basic wildcard DNS detection to avoid false positives.
- **HTTP/HTTPS probing** with status codes, page titles, server headers,
  cookies, body hash.
- **Technology fingerprinting** -- automatically detects 40+ technologies
  (WordPress, Jenkins, Jira, Grafana, Elasticsearch, etc.) from HTTP
  responses and flags high-value targets known to have frequent CVEs.
- **WAF detection** -- identifies Cloudflare, Akamai, Imperva, AWS WAF,
  Sucuri, F5 BIG-IP, Barracuda, Fastly, DDoS-Guard, and more. Outputs
  `nowaf_targets.txt` with hosts that have no WAF (priority targets).
- **Third-party / CDN detection** -- identifies subdomains pointing to
  Shopify, GitHub Pages, Heroku, AWS CloudFront, Azure, Vercel, Netlify,
  and 50+ other services via CNAME analysis. Outputs `direct_origins.txt`
  with hosts that are not behind third-party infrastructure.
- **Interesting subdomain tagger** -- scores and tags subdomains matching
  patterns associated with admin panels, staging environments, APIs, CI/CD,
  databases, internal tools and more. Priority-sorted output.
- **Port scanning** -- async scan of 35+ high-value ports (Redis, MongoDB,
  Kubernetes API, Elasticsearch, etc.) on resolved hosts.
- **CNAME subdomain takeover detection** with 45+ service fingerprints.
- **Permutation/mutation** wordlist to discover hidden subdomains.
- **Recursive enumeration** -- automatically re-enumerates discovered
  sub-zones (e.g. `*.internal.example.com`) for deeper coverage.
- **Diff mode** to compare against previous scans and spot new targets.
- **Webhook notifications** -- Discord, Slack or generic JSON webhooks for
  continuous monitoring workflows.
- **Offensive output** -- `httpx_output.jsonl` (compatible with nuclei,
  katana, httpx), `nowaf_targets.txt`, `direct_origins.txt`, and
  `commands.txt` with ready-to-run commands for gowitness, nuclei, ffuf,
  katana and nmap.
- **Next Steps summary** -- after each scan, shows the top 10 targets to
  investigate first, prioritised by takeover risk, high-value tech
  without WAF, interesting subdomains with open ports, and direct origins.
- Tool-friendly outputs: txt, JSONL, JSON, CSV, IPs list, Burp scope,
  live URLs, Nuclei targets, interesting targets, technologies, ports.
- Structured JSON output with per-subdomain metadata.
- Statistics per domain and per source.
- Graceful degradation -- missing API keys or binaries are skipped
  automatically.

## Requirements

- Python 3.12+
- (Optional) [subfinder](https://github.com/projectdiscovery/subfinder) and
  [amass](https://github.com/owasp-amass/amass) binaries in `$PATH`.

## Installation

```bash
git clone git@github.com:YOUR_USER/BBTools.git
cd BBTools
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

### API keys

Copy the example env file and fill in any keys you have:

```bash
cp .env.example .env
```

```env
VT_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook
```

Sources whose keys are missing will be skipped silently. The 6 free sources
(crt.sh, AlienVault OTX, HackerTarget, Wayback, RapidDNS, Anubis) work
without any keys.

### YAML config (optional)

Copy and edit the example config to tune concurrency, timeouts and resolvers:

```bash
cp config.example.yaml config.yaml
```

See `config.example.yaml` for all available options.

## Usage

### Prepare an input file

Create `domains.txt` with one root domain per line. Lines starting with `#`
are treated as comments and blank lines are ignored.

```text
# My targets
example.com
target.org
```

### Run enumeration

```bash
# Full enumeration (all available sources + HTTP probing + tech + WAF detection)
python -m subenum.main run -i domains.txt

# Full offensive recon (everything enabled)
python -m subenum.main run -i domains.txt --permutate --recursive --scan-ports

# Skip HTTP probing (faster, DNS-only)
python -m subenum.main run -i domains.txt --skip-probe

# Use specific sources only
python -m subenum.main run -i domains.txt --sources crtsh,subfinder,alienvault

# Compare against a previous scan
python -m subenum.main run -i domains.txt --diff output/20260325_132129

# With a custom config file
python -m subenum.main run -i domains.txt --config config.yaml
```

### Diff two previous scans

```bash
python -m subenum.main diff output/20260325_132129 output/20260326_091500
```

### Check tool/key availability

```bash
python -m subenum.main doctor
```

## Output

Results are saved to `output/<YYYYMMDD_HHMMSS>/` with the following files:

| File | Description |
|---|---|
| `all_subdomains.txt` | All unique subdomains found (one per line) |
| `resolved_subdomains.txt` | Only subdomains that resolved via DNS |
| `live_hosts.txt` | Live HTTP/HTTPS URLs |
| `nuclei_targets.txt` | One URL per subdomain (prefers HTTPS) for `nuclei -l` |
| `nowaf_targets.txt` | Live hosts without WAF -- priority targets for manual testing |
| `direct_origins.txt` | Live hosts not behind third-party CDN/SaaS -- origin servers |
| `httpx_output.jsonl` | One JSON per line, compatible with httpx/nuclei/katana pipelines |
| `interesting.txt` | Priority-scored interesting targets with tags |
| `ips.txt` | Unique IPs for port scanning with nmap/masscan |
| `scope.txt` | `*.domain` format for Burp Suite scope import |
| `takeover_candidates.txt` | Potential CNAME takeover targets |
| `technologies.json` | Detected technologies per subdomain |
| `ports.json` | Open ports per host from port scanning |
| `commands.txt` | Ready-to-run commands for gowitness, nuclei, ffuf, katana, nmap |
| `subdomains.json` | Full metadata per subdomain (see below) |
| `subdomains.csv` | Same data in CSV format for spreadsheets |
| `stats.json` | Counts, technology summary, elapsed time |
| `diff.json` | Delta vs previous scan (if `--diff` was used) |

### JSON entry format

Each entry in `subdomains.json` looks like:

```json
{
  "root_domain": "example.com",
  "subdomain": "api.example.com",
  "sources": ["crtsh", "alienvault", "subfinder"],
  "resolved": true,
  "a_records": ["93.184.216.34"],
  "aaaa_records": [],
  "cname_records": [],
  "third_party": "",
  "http_status": 200,
  "https_status": 200,
  "http_title": "API Documentation",
  "http_server": "nginx/1.24",
  "http_content_length": 4523,
  "body_hash": "a1b2c3d4e5f67890",
  "cookies": ["session", "csrf_token"],
  "waf": [],
  "technologies": [
    {"name": "Nginx", "version": "1.24", "category": "server"},
    {"name": "React", "version": "", "category": "frontend"}
  ],
  "high_value_techs": [],
  "interesting": true,
  "interesting_score": 7,
  "interesting_tags": ["api"],
  "interesting_reason": "API endpoint",
  "open_ports": {"443": "HTTPS", "8080": "Alt HTTP", "9200": "Elasticsearch"}
}
```

### Interesting targets format

The `interesting.txt` file is sorted by priority score (1-10):

```text
[ 9] admin.example.com     admin     Admin panel
[ 9] jenkins.example.com   cicd      Jenkins CI
[ 8] staging.example.com   dev       Staging environment
[ 8] grafana.example.com   monitoring  Grafana
[ 7] api.example.com       api       API endpoint
```

### Webhook notifications

Set `WEBHOOK_URL` in your `.env` file to receive scan summaries via Discord,
Slack or any generic JSON webhook. Particularly useful combined with `--diff`
for monitoring workflows -- get alerted when new subdomains appear.

## CLI flags

| Flag | Description |
|---|---|
| `-i`, `--input` | Path to domains file (required) |
| `--sources` | Comma-separated source names |
| `--config` | Path to config YAML |
| `--only-resolved` | Export only resolved subdomains in JSON |
| `--skip-probe` | Skip HTTP/HTTPS probing |
| `--permutate` | Generate and resolve permutation candidates |
| `--recursive` | Re-enumerate discovered sub-zones |
| `--scan-ports` | Port scan resolved hosts |
| `--diff` | Compare against a previous output directory |

## Available sources

| Source | Type | Key required |
|---|---|---|
| crt.sh | Certificate Transparency | No |
| AlienVault OTX | Passive DNS | No |
| HackerTarget | Host search | No |
| Wayback Machine | Historical URLs | No |
| RapidDNS | DNS database | No |
| Anubis DB | Subdomain DB | No |
| VirusTotal | API | `VT_API_KEY` |
| urlscan.io | API | `URLSCAN_API_KEY` |
| subfinder | External binary | No (install binary) |
| amass | External binary | No (install binary) |

## Project structure

```
subenum/
  __init__.py        Package init + version
  main.py            CLI (Typer) and orchestration
  config.py          YAML + .env config loading
  sources.py         10 passive source implementations
  dns_utils.py       DNS resolution + wildcard detection
  http_probe.py      HTTP/HTTPS probing + tech + WAF detection
  tech_detect.py     Technology + WAF fingerprint rules
  scope_check.py     Third-party / CDN detection via CNAME
  interesting.py     Interesting subdomain tagger + scoring
  ports.py           Async port scanning (35+ ports)
  takeover.py        CNAME takeover detection
  permutations.py    Subdomain permutation generation
  notify.py          Webhook notifications (Discord/Slack)
  exporters.py       File export (txt/jsonl/json/csv/stats/diff)
```

## Legal disclaimer

**This tool is intended for authorized security testing only.**

- Only use `subenum` against domains you own or have explicit written
  permission to test.
- Ensure your targets are within the scope of a Bug Bounty program or
  engagement agreement.
- Passive reconnaissance still generates network traffic; respect rate limits
  and terms of service of all third-party APIs.
- Port scanning is an active technique -- ensure it is within scope.
- The authors assume no liability for misuse of this tool.
