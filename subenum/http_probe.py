"""HTTP/HTTPS probing for resolved subdomains.

Probes both http:// and https:// for each subdomain, capturing status codes,
page titles, server headers, redirects, response headers, cookies and body
hash. The raw headers/body snippet are passed to tech_detect for fingerprinting.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from subenum.tech_detect import detect_technologies, techs_to_dict, flag_high_value, flag_waf, TechMatch

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class ProbeResult:
    subdomain: str
    http_status: int | None = None
    https_status: int | None = None
    http_title: str = ""
    http_redirect: str = ""
    http_server: str = ""
    http_content_length: int = 0
    body_hash: str = ""
    cookies: list[str] = field(default_factory=list)
    response_headers: dict[str, str] = field(default_factory=dict)
    technologies: list[dict] = field(default_factory=list)
    high_value_techs: list[str] = field(default_factory=list)
    waf: list[str] = field(default_factory=list)
    live_urls: list[str] = field(default_factory=list)


async def _probe_scheme(
    client: httpx.AsyncClient, url: str
) -> tuple[int | None, str, str, str, int, str, dict[str, str], list[str], str]:
    """Probe a URL. Returns (status, title, final_url, server, cl, body_hash, headers, cookies, body_snippet)."""
    try:
        resp = await client.get(url, follow_redirects=True)
        body_bytes = resp.content
        body_text = resp.text[:8192]
        title = ""
        m = _TITLE_RE.search(body_text[:4096])
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        server = resp.headers.get("server", "")
        cl = int(resp.headers.get("content-length", 0)) or len(body_bytes)
        final_url = str(resp.url) if str(resp.url) != url else ""
        body_hash = hashlib.sha256(body_bytes[:16384]).hexdigest()[:16]

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        cookies = [
            c.split("=")[0].strip()
            for c in resp.headers.get_list("set-cookie")
            if "=" in c
        ]

        return resp.status_code, title, final_url, server, cl, body_hash, hdrs, cookies, body_text
    except Exception:
        return None, "", "", "", 0, "", {}, [], ""


async def probe_subdomain(
    sub: str, client: httpx.AsyncClient
) -> ProbeResult:
    result = ProbeResult(subdomain=sub)

    http_st, http_title, http_redir, http_srv, http_cl, http_hash, http_hdrs, http_cookies, http_body = (
        await _probe_scheme(client, f"http://{sub}")
    )
    https_st, https_title, https_redir, https_srv, https_cl, https_hash, https_hdrs, https_cookies, https_body = (
        await _probe_scheme(client, f"https://{sub}")
    )

    result.http_status = http_st
    result.https_status = https_st
    result.http_title = https_title or http_title
    result.http_redirect = https_redir or http_redir
    result.http_server = https_srv or http_srv
    result.http_content_length = https_cl or http_cl
    result.body_hash = https_hash or http_hash
    result.cookies = list(set(https_cookies + http_cookies))

    merged_hdrs = {**http_hdrs, **https_hdrs}
    result.response_headers = merged_hdrs

    best_body = https_body or http_body
    cookie_str = "; ".join(f"{c}=x" for c in result.cookies)
    techs = detect_technologies(merged_hdrs, best_body, cookie_str)
    result.technologies = techs_to_dict(techs)
    result.high_value_techs = flag_high_value(techs)
    result.waf = flag_waf(techs)

    if https_st is not None:
        result.live_urls.append(f"https://{sub}")
    if http_st is not None:
        result.live_urls.append(f"http://{sub}")

    return result


async def probe_batch(
    subdomains: list[str],
    cfg: "Settings",
) -> list[ProbeResult]:
    """Probe a list of subdomains for HTTP/HTTPS concurrently."""
    timeout = 10
    concurrency = min(cfg.concurrency, 20)
    sem = asyncio.Semaphore(concurrency)

    async def _probe_one(sub: str, client: httpx.AsyncClient) -> ProbeResult:
        async with sem:
            return await probe_subdomain(sub, client)

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True,
        limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
    ) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]HTTP probing"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            ptask = progress.add_task("probing", total=len(subdomains))
            tasks = [_probe_one(s, client) for s in subdomains]
            results: list[ProbeResult] = []
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                progress.advance(ptask)

    # Report technology summary
    all_techs: dict[str, int] = {}
    all_hv: list[str] = []
    for r in results:
        for t in r.technologies:
            all_techs[t["name"]] = all_techs.get(t["name"], 0) + 1
        all_hv.extend(r.high_value_techs)

    if all_techs:
        top = sorted(all_techs.items(), key=lambda x: -x[1])[:10]
        tech_str = ", ".join(f"{n}({c})" for n, c in top)
        console.print(f"[dim]Tech detected: {tech_str}[/]")

    if all_hv:
        unique_hv = sorted(set(all_hv))
        console.print(f"[bold red]High-value targets: {', '.join(unique_hv)}[/]")

    waf_count = sum(1 for r in results if r.waf)
    nowaf_live = sum(1 for r in results if r.live_urls and not r.waf)
    if waf_count:
        console.print(f"[dim]WAF detected on {waf_count} hosts, {nowaf_live} live without WAF[/]")

    return results
