"""Shodan host enrichment for resolved IPs.

Queries the Shodan HostInfo API for each unique IP discovered in the scan,
enriching entries with open ports, service banners, OS info, tags, and CVEs.
Requires SHODAN_API_KEY environment variable.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


@dataclass
class ShodanHostData:
    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    os: str = ""
    org: str = ""
    isp: str = ""
    country: str = ""
    tags: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    banners: list[dict] = field(default_factory=list)  # [{port, transport, product, version, banner}]
    vulns: list[dict] = field(default_factory=list)    # [{cve, cvss, summary}]


class _ShodanPlanError(Exception):
    """Raised when Shodan returns 403 (host API requires paid plan)."""


async def _fetch_host(
    ip: str, api_key: str, client: httpx.AsyncClient
) -> ShodanHostData | None:
    try:
        resp = await client.get(
            _SHODAN_HOST_URL.format(ip=ip),
            params={"key": api_key},
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            console.print("[yellow]\\[shodan] Invalid API key — check SHODAN_API_KEY[/]")
            return None
        if resp.status_code == 403:
            raise _ShodanPlanError()
        if resp.status_code == 429:
            console.print("[yellow]\\[shodan] Rate limited — slowing down[/]")
            await asyncio.sleep(5)
            return None
        resp.raise_for_status()
        data = resp.json()
    except _ShodanPlanError:
        raise
    except Exception as exc:
        # Avoid leaking the API key that appears in the URL
        msg = str(exc).split("?key=")[0][:80]
        console.print(f"[yellow]\\[shodan] {ip}: {msg}[/]")
        return None

    host = ShodanHostData(ip=ip)
    host.ports = sorted(data.get("ports", []))
    host.hostnames = data.get("hostnames", [])
    host.os = data.get("os") or ""
    host.org = data.get("org") or ""
    host.isp = data.get("isp") or ""
    host.country = data.get("country_name") or ""
    host.tags = data.get("tags") or []

    # CVEs from the top-level vulns dict
    vulns_raw: dict = data.get("vulns", {})
    for cve, info in vulns_raw.items():
        host.cves.append(cve)
        host.vulns.append({
            "cve": cve,
            "cvss": info.get("cvss", ""),
            "summary": (info.get("summary") or "")[:200],
        })
    host.vulns.sort(key=lambda v: -(float(v["cvss"]) if v["cvss"] else 0))
    host.cves = [v["cve"] for v in host.vulns]

    # Service banners
    for service in data.get("data", []):
        banner: dict = {
            "port": service.get("port"),
            "transport": service.get("transport", "tcp"),
            "product": service.get("product") or "",
            "version": service.get("version") or "",
            "banner": (service.get("data") or "")[:300].strip(),
        }
        host.banners.append(banner)

    return host


async def enrich_with_shodan(
    all_entries: list[dict],
    cfg: "Settings",
) -> dict[str, ShodanHostData]:
    """Query Shodan for every unique IP in all_entries. Returns {ip: ShodanHostData}."""
    if not cfg.shodan_key:
        return {}

    # Collect unique IPs
    unique_ips: set[str] = set()
    for entry in all_entries:
        unique_ips.update(entry.get("a_records", []))

    if not unique_ips:
        return {}

    console.print(f"[bold]Shodan:[/] enriching {len(unique_ips)} unique IP(s)...")

    results: dict[str, ShodanHostData] = {}
    ip_list = sorted(unique_ips)

    async with httpx.AsyncClient(timeout=15) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Shodan lookup"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task_bar = progress.add_task("enriching", total=len(ip_list))
            for ip in ip_list:
                try:
                    data = await _fetch_host(ip, cfg.shodan_key, client)
                except _ShodanPlanError:
                    progress.stop()
                    console.print(
                        "[yellow]\\[shodan] 403 — host lookup requires a paid Shodan plan. "
                        "Skipping remaining IPs.[/]"
                    )
                    break
                if data is not None:
                    results[data.ip] = data
                progress.advance(task_bar)
                await asyncio.sleep(1.1)  # Shodan free tier: 1 req/sec

    found = len(results)
    cve_hosts = sum(1 for h in results.values() if h.cves)
    console.print(f"[bold blue]Shodan:[/] {found}/{len(unique_ips)} IPs found, {cve_hosts} with CVEs")

    if cve_hosts:
        # Surface hosts with critical CVEs
        for host in sorted(results.values(), key=lambda h: len(h.cves), reverse=True)[:5]:
            if host.cves:
                console.print(
                    f"  [bold red]{host.ip}[/] ({host.org}) — CVEs: {', '.join(host.cves[:5])}"
                )

    return results


def export_shodan(
    shodan_results: dict[str, ShodanHostData],
    all_entries: list[dict],
    out_dir: Path,
) -> None:
    if not shodan_results:
        return

    # Build IP → subdomains map for context
    ip_to_subs: dict[str, list[str]] = {}
    for entry in all_entries:
        for ip in entry.get("a_records", []):
            ip_to_subs.setdefault(ip, []).append(entry["subdomain"])

    records: list[dict] = []
    for ip, host in sorted(shodan_results.items()):
        records.append({
            "ip": ip,
            "subdomains": sorted(ip_to_subs.get(ip, [])),
            "org": host.org,
            "isp": host.isp,
            "country": host.country,
            "os": host.os,
            "ports": host.ports,
            "tags": host.tags,
            "cves": host.cves,
            "vulns": host.vulns,
            "banners": host.banners,
        })

    (out_dir / "shodan_enrichment.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n"
    )

    # Human-readable summary
    lines = ["# Shodan Enrichment", ""]
    cve_records = [r for r in records if r["cves"]]
    if cve_records:
        lines.append(f"## IPs with CVEs ({len(cve_records)})")
        lines.append("")
        for r in sorted(cve_records, key=lambda x: len(x["cves"]), reverse=True):
            subs = ", ".join(r["subdomains"][:3])
            lines.append(f"  {r['ip']} ({r['org']}) — {subs}")
            for v in r["vulns"][:5]:
                lines.append(f"    [{v['cvss']}] {v['cve']}: {v['summary'][:100]}")
            lines.append("")

    lines.append(f"## All hosts ({len(records)})")
    lines.append("")
    for r in records:
        subs = ", ".join(r["subdomains"][:3])
        port_str = ", ".join(str(p) for p in r["ports"][:10])
        lines.append(f"  {r['ip']} | {r['org']} | {r['country']} | ports: {port_str}")
        if subs:
            lines.append(f"    subs: {subs}")

    (out_dir / "shodan_enrichment.txt").write_text("\n".join(lines) + "\n")
    console.print(f"[dim]Shodan enrichment → {out_dir}/shodan_enrichment.json[/]")
