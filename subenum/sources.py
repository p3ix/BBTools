"""Passive subdomain enumeration sources.

Each source is an async function returning a set of discovered subdomains.
External binaries (subfinder, amass) are wrapped via asyncio subprocess.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from rich.console import Console

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_error(source: str, exc: Exception) -> str:
    """Produce a concise one-line warning for source failures."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"[yellow]\\[{source}] HTTP {exc.response.status_code}[/]"
    msg = str(exc).split("\n")[0][:80]
    return f"[yellow]\\[{source}] {msg}[/]"


def _is_enabled(cfg: "Settings", name: str) -> bool:
    return cfg.source(name).enabled


def _has_binary(name: str, cfg: "Settings") -> str | None:
    """Return the resolved path to a binary, or None."""
    custom = cfg.source(name).path
    return shutil.which(custom or name)


async def _run_binary(
    cmd: list[str], timeout: int, source_name: str
) -> set[str]:
    """Run an external binary and collect stdout lines."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        console.print(f"[yellow]\\[{source_name}] timed out after {timeout}s[/]")
        try:
            proc.kill()  # type: ignore[union-attr]
        except ProcessLookupError:
            pass
        return set()
    except FileNotFoundError:
        console.print(f"[yellow]\\[{source_name}] binary not found[/]")
        return set()

    if proc.returncode != 0:
        snippet = (stderr or b"").decode(errors="replace").strip()[:200]
        console.print(f"[yellow]\\[{source_name}] exited {proc.returncode}: {snippet}[/]")

    lines = stdout.decode(errors="replace").splitlines()
    return {line.strip().lower() for line in lines if line.strip()}


# ===================================================================
# Sources
# ===================================================================

async def fetch_crtsh(domain: str, cfg: "Settings") -> set[str]:
    src = cfg.source("crtsh")
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=src.timeout, verify=False) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            entries = resp.json()
    except Exception as exc:
        console.print(_short_error("crtsh", exc))
        return set()

    subs: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]  # *.sub.example.com → sub.example.com
            subs.add(name)
    return subs


async def fetch_virustotal(domain: str, cfg: "Settings") -> set[str]:
    if not cfg.virustotal_key:
        return set()
    src = cfg.source("virustotal")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": cfg.virustotal_key, "Accept": "application/json"}

    subs: set[str] = set()
    cursor: str | None = None
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            while True:
                params: dict[str, str] = {"limit": "40"}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                body = resp.json()
                for item in body.get("data", []):
                    sub_id = item.get("id", "").lower()
                    if sub_id:
                        subs.add(sub_id)
                cursor = body.get("meta", {}).get("cursor")
                if not cursor or not body.get("data"):
                    break
    except Exception as exc:
        console.print(_short_error("virustotal", exc))
    return subs


async def fetch_urlscan(domain: str, cfg: "Settings") -> set[str]:
    if not cfg.urlscan_key:
        return set()
    src = cfg.source("urlscan")
    url = "https://urlscan.io/api/v1/search/"
    headers = {"API-Key": cfg.urlscan_key, "Accept": "application/json"}
    params = {"q": f"domain:{domain}", "size": "1000"}
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("urlscan", exc))
        return set()

    subs: set[str] = set()
    for result in data.get("results", []):
        host = result.get("page", {}).get("domain", "").lower().strip()
        if host:
            subs.add(host)
    return subs


async def fetch_subfinder(domain: str, cfg: "Settings") -> set[str]:
    binary = _has_binary("subfinder", cfg)
    if not binary:
        return set()
    src = cfg.source("subfinder")
    return await _run_binary(
        [binary, "-d", domain, "-silent"], src.timeout, "subfinder"
    )


async def fetch_amass(domain: str, cfg: "Settings") -> set[str]:
    binary = _has_binary("amass", cfg)
    if not binary:
        return set()
    src = cfg.source("amass")
    return await _run_binary(
        [binary, "enum", "-passive", "-d", domain], src.timeout, "amass"
    )


async def fetch_alienvault(domain: str, cfg: "Settings") -> set[str]:
    src = cfg.source("alienvault")
    base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
    subs: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=src.timeout, follow_redirects=True) as client:
            resp = await client.get(f"{base}/passive_dns")
            if resp.status_code == 429:
                console.print(f"[yellow]\\[alienvault] rate limited for {domain}[/]")
                return set()
            resp.raise_for_status()
            for record in resp.json().get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname:
                    subs.add(hostname)
            resp2 = await client.get(f"{base}/url_list")
            if resp2.status_code != 429:
                resp2.raise_for_status()
                for record in resp2.json().get("url_list", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname:
                        subs.add(hostname)
    except Exception as exc:
        console.print(_short_error("alienvault", exc))
    return subs


async def fetch_hackertarget(domain: str, cfg: "Settings") -> set[str]:
    src = cfg.source("hackertarget")
    url = "https://api.hackertarget.com/hostsearch/"
    params = {"q": domain}
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            text = resp.text
    except Exception as exc:
        console.print(_short_error("hackertarget", exc))
        return set()

    if "error" in text.lower() or "API count exceeded" in text:
        console.print(f"[yellow]\\[hackertarget] rate limited or error[/]")
        return set()

    subs: set[str] = set()
    for line in text.splitlines():
        host = line.split(",")[0].strip().lower()
        if host:
            subs.add(host)
    return subs


async def fetch_wayback(domain: str, cfg: "Settings") -> set[str]:
    """Extract subdomains from Wayback Machine CDX index."""
    src = cfg.source("wayback")
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "5000",
    }
    try:
        async with httpx.AsyncClient(timeout=src.timeout, follow_redirects=True) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            rows = resp.json()
    except Exception as exc:
        console.print(_short_error("wayback", exc))
        return set()

    subs: set[str] = set()
    for row in rows[1:]:  # first row is the header ["original"]
        try:
            host = urlparse(row[0]).hostname
            if host:
                subs.add(host.lower())
        except Exception:
            continue
    return subs


async def fetch_rapiddns(domain: str, cfg: "Settings") -> set[str]:
    """Scrape subdomains from rapiddns.io HTML table."""
    src = cfg.source("rapiddns")
    url = f"https://rapiddns.io/subdomain/{domain}"
    params = {"full": "1"}
    try:
        async with httpx.AsyncClient(timeout=src.timeout, follow_redirects=True) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            html = resp.text
    except Exception as exc:
        console.print(_short_error("rapiddns", exc))
        return set()

    pattern = re.compile(r"(?i)([a-z0-9][-a-z0-9]*\.)*" + re.escape(domain))
    return {m.group(0).lower() for m in pattern.finditer(html) if m.group(0).lower() != domain}


async def fetch_anubis(domain: str, cfg: "Settings") -> set[str]:
    src = cfg.source("anubis")
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        async with httpx.AsyncClient(timeout=src.timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("anubis", exc))
        return set()

    if isinstance(data, list):
        return {s.strip().lower() for s in data if isinstance(s, str) and s.strip()}
    return set()


async def fetch_threatminer(domain: str, cfg: "Settings") -> set[str]:
    """Passive DNS data from ThreatMiner (free, no key required)."""
    src = cfg.source("threatminer")
    url = "https://api.threatminer.org/v2/domain.php"
    params = {"q": domain, "rt": "5"}
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("threatminer", exc))
        return set()

    results = data.get("results", [])
    if not isinstance(results, list):
        return set()
    return {s.strip().lower() for s in results if isinstance(s, str) and s.strip()}


async def fetch_bufferover(domain: str, cfg: "Settings") -> set[str]:
    """TLS scan data from BufferOver/Tls.BufferOver.run (free, no key required)."""
    src = cfg.source("bufferover")
    url = "https://tls.bufferover.run/dns"
    params = {"q": f".{domain}"}
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("bufferover", exc))
        return set()

    subs: set[str] = set()
    # FDNS_A entries are "IP,subdomain" pairs
    for entry in data.get("FDNS_A", []) or []:
        if "," in entry:
            host = entry.split(",", 1)[1].strip().lower()
            if host:
                subs.add(host)
    # RDNS entries are plain hostnames
    for entry in data.get("RDNS", []) or []:
        host = entry.strip().lower()
        if host:
            subs.add(host)
    return subs


async def fetch_chaos(domain: str, cfg: "Settings") -> set[str]:
    """ProjectDiscovery Chaos dataset (requires CHAOS_API_KEY)."""
    if not cfg.chaos_key:
        return set()
    src = cfg.source("chaos")
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    headers = {"Authorization": cfg.chaos_key}
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 401:
                console.print("[yellow]\\[chaos] invalid API key[/]")
                return set()
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("chaos", exc))
        return set()

    # API returns {"subdomains": ["api", "www", ...], "domain": "example.com"}
    # Each entry is a label prefix, not a full FQDN
    raw_subs = data.get("subdomains", [])
    if not isinstance(raw_subs, list):
        return set()
    return {f"{s.strip().lower()}.{domain}" for s in raw_subs if isinstance(s, str) and s.strip()}


async def fetch_github(domain: str, cfg: "Settings") -> set[str]:
    """Search GitHub public code for subdomain references (GITHUB_TOKEN optional)."""
    src = cfg.source("github")
    url = "https://api.github.com/search/code"
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if cfg.github_token:
        headers["Authorization"] = f"Bearer {cfg.github_token}"

    # Regex to extract FQDNs belonging to the target domain from text snippets
    _sub_re = re.compile(
        r"(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\."
        + re.escape(domain)
        + r")"
    )

    subs: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=src.timeout) as client:
            params = {"q": f'"{domain}"', "per_page": "100"}
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 403:
                console.print("[yellow]\\[github] rate limited — set GITHUB_TOKEN to increase limits[/]")
                return set()
            if resp.status_code == 422:
                return set()
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        console.print(_short_error("github", exc))
        return set()

    for item in data.get("items", []):
        # Extract from repository name + path
        for field in ("path", "name"):
            for m in _sub_re.finditer(item.get(field, "")):
                subs.add(m.group(1).lower())
        # Extract from text_matches snippets (available with the right Accept header)
        for match in item.get("text_matches", []):
            for m in _sub_re.finditer(match.get("fragment", "")):
                subs.add(m.group(1).lower())

    return subs


# ---------------------------------------------------------------------------
# Registry & orchestrator
# ---------------------------------------------------------------------------

SOURCE_REGISTRY: dict[str, callable] = {
    "crtsh":          fetch_crtsh,
    "virustotal":     fetch_virustotal,
    "urlscan":        fetch_urlscan,
    "subfinder":      fetch_subfinder,
    "amass":          fetch_amass,
    "alienvault":     fetch_alienvault,
    "hackertarget":   fetch_hackertarget,
    "wayback":        fetch_wayback,
    "rapiddns":       fetch_rapiddns,
    "anubis":         fetch_anubis,
    "threatminer":    fetch_threatminer,
    "bufferover":     fetch_bufferover,
    "chaos":          fetch_chaos,
    "github":         fetch_github,
}


async def gather_subdomains(
    domain: str,
    cfg: "Settings",
    only_sources: list[str] | None = None,
) -> dict[str, set[str]]:
    """Run enabled sources in parallel and return {source_name: {subdomains}}."""

    chosen = only_sources or list(SOURCE_REGISTRY)
    tasks: dict[str, asyncio.Task] = {}

    for name in chosen:
        func = SOURCE_REGISTRY.get(name)
        if func is None:
            console.print(f"[yellow]Unknown source: {name}[/]")
            continue
        if not _is_enabled(cfg, name):
            continue
        tasks[name] = asyncio.create_task(func(domain, cfg))

    results: dict[str, set[str]] = {}
    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as exc:
            console.print(f"[yellow]\\[{name}] unexpected error: {exc}[/]")
            results[name] = set()

    return results
