# subenum

Active and passive subdomain enumeration CLI for Bug Bounty reconnaissance.

`subenum` reads a list of root domains, queries multiple passive sources in
parallel, brute-forces DNS with custom wordlists, generates smart permutations,
validates results via DNS, probes for live HTTP services, fingerprints
technologies, detects WAFs, identifies third-party services, detects potential
CNAME takeovers, extracts endpoints and secrets from JavaScript files, and
exports everything to structured output files ready for your Bug Bounty workflow.

Designed to run unattended on a VPS with full resume support after connection drops.

---

## Features

### Discovery
- **10 passive sources** — crt.sh, VirusTotal, urlscan.io, AlienVault OTX,
  HackerTarget, Wayback Machine, RapidDNS, Anubis DB, subfinder and amass.
- **6 free sources** that require no API key (crt.sh, AlienVault, HackerTarget,
  Wayback, RapidDNS, Anubis).
- **DNS brute-force** (`--bruteforce --wordlist`) — resolves every word in a
  custom wordlist as `word.domain`. Supports any txt wordlist with `#` comments.
- **Permutation/mutation engine** (`--permutate`) — generates label combinations
  from discovered subdomains. Accepts an external wordlist (`--wordlist`) to
  expand coverage; caps at 2 000 words to avoid combinatorial explosion (full
  wordlist is used for flat brute-force).
- **Recursive enumeration** (`--recursive`) — automatically re-enumerates
  discovered sub-zones (e.g. `*.internal.example.com`) for deeper coverage.
- DNS validation (A / AAAA / CNAME) with configurable resolvers and wildcard
  detection to eliminate false positives.
- Parallel async execution throughout for maximum speed.

### Analysis
- **HTTP/HTTPS probing** — status codes, page titles, server headers, cookies,
  body hash, live URL detection.
- **Technology fingerprinting** — detects 40+ technologies (WordPress, Jenkins,
  Jira, Grafana, Elasticsearch, etc.) and flags high-value targets with frequent CVEs.
- **WAF detection** — identifies Cloudflare, Akamai, Imperva, AWS WAF, Sucuri,
  F5 BIG-IP, Barracuda, Fastly, DDoS-Guard and more.
- **Third-party / CDN detection** — identifies subdomains pointing to Shopify,
  GitHub Pages, Heroku, CloudFront, Azure, Vercel, Netlify and 50+ other
  services via CNAME analysis.
- **Interesting subdomain tagger** — scores (1–10) and tags subdomains matching
  patterns for admin panels, staging environments, APIs, CI/CD, databases,
  internal tools and more.
- **Port scanning** (`--scan-ports`) — async scan of 35+ high-value ports
  (Redis, MongoDB, Kubernetes API, Elasticsearch, etc.) on resolved hosts.
- **CNAME subdomain takeover detection** with 45+ service fingerprints.

### JavaScript analysis
- **JS extraction** (`--js`) — crawls live hosts, fetches all JavaScript files
  and extracts:
  - **Endpoints** — LinkFinder regex (battle-tested bug bounty pattern) plus 8
    semantic patterns covering REST paths, GraphQL, S3 buckets, Firebase URLs
    and more.
  - **Secrets** — 20 families: AWS keys, GCP/Firebase tokens, Stripe/Slack/
    Twilio/SendGrid keys, JWT tokens, private keys, generic high-entropy strings
    and more. Filtered with Shannon entropy (≥ 3.3 bits/char) and placeholder
    detection to minimize false positives.
  - **Subdomains** — domain references inside JS bundles that passive sources miss.
  - Handles minified/webpack bundles via **jsbeautifier** before applying regex,
    dramatically improving coverage on modern SPAs.

### Workflow
- **Resume / checkpoint** (`--resume <output_dir>`) — persists per-domain
  progress to `.checkpoint.json` after each domain completes. Resume a
  VPS run after a connection drop without losing completed work.
- **Diff mode** (`--diff`) — compare against a previous scan and surface new targets.
- **Webhook notifications** — Discord, Slack or generic JSON webhooks for
  continuous monitoring workflows.
- **Next Steps summary** — after each scan shows the top 10 targets to
  investigate first, prioritised by takeover risk, high-value tech without WAF,
  interesting subdomains with open ports and direct origins.

---

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

Sources whose keys are missing are skipped silently. The 6 free sources work
without any keys.

### YAML config (optional)

Copy and edit the example config to tune concurrency, timeouts and resolvers:

```bash
cp config.example.yaml config.yaml
```

See `config.example.yaml` for all available options.

---

## Usage

### Prepare an input file

```text
# domains.txt
example.com
target.org
```

### Common invocations

```bash
# Passive enumeration only (fast, no active requests)
python -m subenum.main run -i domains.txt --skip-probe

# Full passive + probing + WAF/tech detection
python -m subenum.main run -i domains.txt

# Full recon with permutations and recursive enumeration
python -m subenum.main run -i domains.txt --permutate --recursive

# Add DNS brute-force with a custom wordlist
python -m subenum.main run -i domains.txt \
  --bruteforce --wordlist wordlists/combined.txt \
  --permutate --recursive

# Full offensive recon (everything enabled)
python -m subenum.main run -i domains.txt \
  --bruteforce --wordlist wordlists/combined.txt \
  --permutate --recursive --scan-ports --js

# Compare against a previous scan
python -m subenum.main run -i domains.txt --diff output/20260325_132129
```

### Resume after a connection drop

```bash
# Initial run
python -m subenum.main run -i domains.txt \
  --bruteforce --wordlist wordlists/combined.txt \
  --permutate --recursive --js

# Connection dropped — resume from the same output directory
python -m subenum.main run -i domains.txt \
  --bruteforce --wordlist wordlists/combined.txt \
  --permutate --recursive --js \
  --resume output/20260514_103045
```

Completed domains are loaded from the checkpoint and skipped. Only the
in-progress domain at the time of interruption is re-processed.

### Run unattended on a VPS

```bash
nohup python -m subenum.main run -i domains.txt \
  --bruteforce --wordlist wordlists/combined.txt \
  --permutate --recursive --js \
  > scan.log 2>&1 &

# Monitor progress
tail -f scan.log
```

Or with `screen` to keep the rich progress bars visible:

```bash
screen -S scan
python -m subenum.main run -i domains.txt --bruteforce --wordlist wordlists/combined.txt --permutate --recursive --js
# Ctrl+A, D  →  detach without killing the process
screen -r scan   # reattach later
```

### Diff two previous scans

```bash
python -m subenum.main diff output/20260325_132129 output/20260326_091500
```

### Check tool and key availability

```bash
python -m subenum.main doctor
```

---

## Output

Results are saved to `output/<YYYYMMDD_HHMMSS>/`. When `--resume` is used the
same directory is reused.

| File | Description |
|---|---|
| `subdomains.json` | Full metadata per subdomain (DNS, HTTP, WAF, tech, ports, takeover, score) |
| `all_subdomains.txt` | All unique subdomains found, one per line |
| `resolved_subdomains.txt` | Only subdomains that resolved via DNS |
| `live_hosts.txt` | Live HTTP/HTTPS URLs |
| `nuclei_targets.txt` | One URL per subdomain (prefers HTTPS) for `nuclei -l` |
| `nowaf_targets.txt` | Live hosts without WAF — priority targets for manual testing |
| `httpx_output.jsonl` | One JSON per line, compatible with httpx / nuclei / katana pipelines |
| `interesting.txt` | Priority-scored interesting targets with tags |
| `ips.txt` | Unique resolved IPs for nmap / masscan |
| `scope.txt` | `*.domain` format for Burp Suite scope import |
| `takeover_candidates.txt` | Potential CNAME takeover targets |
| `ports.json` | Open ports per host from port scanning |
| `js_findings.json` | Full JS analysis: endpoints, secrets and subdomains per host |
| `js_endpoints.txt` | All unique endpoints extracted from JS files |
| `js_secrets.txt` | Secrets found in JS (values masked) |
| `js_subdomains.txt` | Subdomains discovered inside JS bundles |
| `commands.txt` | Ready-to-run commands for gowitness, nuclei, ffuf, katana, nmap |
| `stats.json` | Counts, technology summary, elapsed time |
| `diff.json` | Delta vs previous scan (if `--diff` was used) |
| `.checkpoint.json` | Resume state (one entry per completed domain) |

### subdomains.json entry format

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
  "open_ports": {"443": "HTTPS", "9200": "Elasticsearch"}
}
```

### interesting.txt format

Sorted by priority score (1–10):

```text
[ 9] admin.example.com      admin       Admin panel
[ 9] jenkins.example.com    cicd        Jenkins CI
[ 8] staging.example.com    dev         Staging environment
[ 8] grafana.example.com    monitoring  Grafana
[ 7] api.example.com        api         API endpoint
```

---

## CLI flags

| Flag | Description |
|---|---|
| `-i`, `--input` | Path to domains file (required) |
| `--sources` | Comma-separated source names to use |
| `--config` | Path to config YAML |
| `--only-resolved` | Export only resolved subdomains in JSON |
| `--skip-probe` | Skip HTTP/HTTPS probing |
| `--permutate` | Generate and resolve permutation candidates |
| `--bruteforce` | DNS brute-force using a wordlist (requires `--wordlist`) |
| `--wordlist` | Path to wordlist for brute-force and/or permutations |
| `--recursive` | Re-enumerate discovered sub-zones |
| `--scan-ports` | Async port scan on resolved hosts |
| `--js` | Fetch and analyse JavaScript files (requires probing) |
| `--resume` | Resume from an existing output directory |
| `--diff` | Compare against a previous output directory |

---

## Wordlists

`wordlists/bb_personal.txt` — curated personal wordlist (~750 words) organized
in 17 sections: Dev/Staging/QA, API & gateway, Auth & identity, Admin panels,
CI/CD & DevOps, Monitoring, Data & databases, Storage, Internal tools, Mail,
Security infrastructure, Cloud & containers, Payment, Mobile, Network services,
Regional instances, and Legacy & forgotten assets.

`wordlists/combined.txt` — `bb_personal.txt` merged with
[SecLists subdomains-top1million-5000](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt),
deduplicated. Recommended default for `--wordlist`.

For deeper coverage, combine with:
- [Assetnote best-dns-wordlist](https://wordlists.assetnote.io) — internet-wide scan data
- [n0kovo_subdomains_medium](https://github.com/n0kovo/n0kovo_subdomains) — ~100k curated entries

```bash
sort -u wordlists/bb_personal.txt seclists_5000.txt n0kovo_medium.txt > wordlists/deep.txt
```

---

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

---

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
  bruteforce.py      DNS brute-force with custom wordlists
  checkpoint.py      Resume / checkpoint persistence
  js_extract.py      JavaScript endpoint, secret and subdomain extraction
  notify.py          Webhook notifications (Discord/Slack)
  exporters.py       File export (txt/jsonl/json/stats/diff)

wordlists/
  bb_personal.txt    Curated personal wordlist (~750 words, 17 sections)
  combined.txt       bb_personal + SecLists top-5000, deduplicated
```

---

## Legal disclaimer

**This tool is intended for authorized security testing only.**

- Only use `subenum` against domains you own or have explicit written
  permission to test.
- Ensure your targets are within the scope of a Bug Bounty program or
  engagement agreement.
- Passive reconnaissance still generates network traffic; respect rate limits
  and terms of service of all third-party APIs.
- Port scanning and JS analysis are active techniques — ensure they are within scope.
- The authors assume no liability for misuse of this tool.
