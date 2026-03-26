"""subenum — Passive subdomain enumeration CLI for Bug Bounty.

Usage:
    python -m subenum.main run -i domains.txt
    python -m subenum.main run -i domains.txt --permutate --scan-ports
    python -m subenum.main run -i domains.txt --recursive --skip-probe
    python -m subenum.main run -i domains.txt --diff output/20260325_132129
    python -m subenum.main diff output/20260325_132129 output/20260326_091500
    python -m subenum.main doctor
    python -m subenum.main version
"""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from subenum import __version__
from subenum.config import Settings, load_settings
from subenum.dns_utils import detect_wildcard, resolve_batch, ResolveResult
from subenum.exporters import build_entries, export_all, standalone_diff
from subenum.http_probe import probe_batch, ProbeResult
from subenum.interesting import tag_interesting, InterestingHit
from subenum.notify import notify_results
from subenum.permutations import generate_permutations
from subenum.ports import scan_batch as port_scan_batch
from subenum.sources import SOURCE_REGISTRY, gather_subdomains
from subenum.takeover import check_takeover, TakeoverCandidate

console = Console(stderr=True)
app = typer.Typer(
    name="subenum",
    help="Passive subdomain enumeration tool for authorized Bug Bounty targets.",
    add_completion=False,
)

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    ver = f"v{__version__}"
    line1 = "   subenum -- subdomain enumerator     "  # 39 chars
    line2 = f"   {ver}{' ' * (36 - len(ver))}"          # 39 chars, dynamic
    console.print(
        "\n[bold cyan]╔═══════════════════════════════════════╗[/]"
        f"\n[bold cyan]║[/][bold white]{line1}[/][bold cyan]║[/]"
        f"\n[bold cyan]║[/]{line2}[bold cyan]║[/]"
        "\n[bold cyan]╚═══════════════════════════════════════╝[/]\n"
    )


def _read_domains(path: Path) -> list[str]:
    if not path.is_file():
        console.print(f"[bold red]File not found: {path}[/]")
        raise typer.Exit(1)

    seen: set[str] = set()
    domains: list[str] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if not _DOMAIN_RE.match(line):
            console.print(f"[yellow]Skipping invalid domain: {raw_line.strip()}[/]")
            continue
        if line in seen:
            continue
        seen.add(line)
        domains.append(line)

    if not domains:
        console.print("[bold red]No valid domains found in input file.[/]")
        raise typer.Exit(1)

    return domains


def _clean_subdomains(
    raw: dict[str, set[str]], root_domain: str
) -> tuple[dict[str, set[str]], set[str]]:
    """Normalise, deduplicate and scope-filter subdomains."""
    cleaned_map: dict[str, set[str]] = {}
    unified: set[str] = set()
    suffix = f".{root_domain}"

    for source, subs in raw.items():
        good: set[str] = set()
        for s in subs:
            s = s.strip().lower()
            if s.startswith("*."):
                s = s[2:]
            if not s or s == root_domain:
                continue
            if not s.endswith(suffix):
                continue
            if not _DOMAIN_RE.match(s):
                continue
            # Reject garbage: prefix must be max 4 labels deep, each ≤30 chars
            prefix = s[: -len(suffix)]
            labels = prefix.split(".")
            if len(labels) > 4:
                continue
            if any(len(lbl) > 30 for lbl in labels):
                continue
            good.add(s)
        cleaned_map[source] = good
        unified |= good

    return cleaned_map, unified


def _print_summary(
    all_entries: list[dict],
    source_counts: dict[str, dict[str, int]],
    takeover_count: int = 0,
    live_count: int = 0,
    interesting_count: int = 0,
    tech_count: int = 0,
    port_hosts: int = 0,
    waf_count: int = 0,
    nowaf_live: int = 0,
    third_party_count: int = 0,
) -> None:
    total = len(all_entries)
    resolved = sum(1 for e in all_entries if e["resolved"])

    table = Table(title="Results Summary", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total subdomains", str(total))
    table.add_row("Resolved", f"[green]{resolved}[/]")
    table.add_row("Unresolved", f"[red]{total - resolved}[/]")
    if live_count:
        table.add_row("Live HTTP hosts", f"[cyan]{live_count}[/]")
    if waf_count:
        table.add_row("Behind WAF", f"[dim]{waf_count}[/]")
    if nowaf_live:
        table.add_row("Live without WAF", f"[bold green]{nowaf_live}[/]")
    if third_party_count:
        table.add_row("Third-party (CDN/SaaS)", f"[dim]{third_party_count}[/]")
    if tech_count:
        table.add_row("Technologies detected", f"[magenta]{tech_count}[/]")
    if interesting_count:
        table.add_row("Interesting targets", f"[bold yellow]{interesting_count}[/]")
    if port_hosts:
        table.add_row("Hosts with extra ports", f"[yellow]{port_hosts}[/]")
    if takeover_count:
        table.add_row("Takeover candidates", f"[bold red]{takeover_count}[/]")
    console.print(table)

    if source_counts:
        src_table = Table(title="Per-source counts", show_lines=True)
        src_table.add_column("Domain", style="bold")
        all_src_names = sorted({s for d in source_counts.values() for s in d})
        for src in all_src_names:
            src_table.add_column(src, justify="right")
        for domain, counts in source_counts.items():
            row = [domain] + [str(counts.get(s, 0)) for s in all_src_names]
            src_table.add_row(*row)
        console.print(src_table)


def _print_action_items(
    all_entries: list[dict],
    all_takeover: list[TakeoverCandidate],
    all_probe_results: list[ProbeResult],
    all_interesting: list[InterestingHit],
    all_port_results: list,
) -> None:
    """Print a prioritised 'Next Steps' panel to guide the hunter."""
    items: list[tuple[int, str, str]] = []  # (priority, subdomain, reason)

    # 1. Takeover candidates (highest priority)
    for c in all_takeover:
        items.append((100, c.subdomain, f"TAKEOVER -> {c.service} ({c.cname})"))

    # Build lookup maps
    probe_map = {p.subdomain: p for p in all_probe_results}
    port_map = {}
    for r in all_port_results:
        extras = {p: s for p, s in r.open_ports.items() if p not in (80, 443)}
        if extras:
            port_map[r.host] = extras
    entry_map = {e["subdomain"]: e for e in all_entries}

    # 2. High-value tech without WAF
    for pr in all_probe_results:
        if pr.high_value_techs and not pr.waf:
            tech_str = ", ".join(pr.high_value_techs)
            score = 90
            items.append((score, pr.subdomain, f"High-value tech (no WAF): {tech_str}"))

    # 3. Interesting subdomains with extra ports, no WAF
    interesting_set = {h.subdomain: h for h in all_interesting}
    for sub, hit in interesting_set.items():
        pr = probe_map.get(sub)
        extras = port_map.get(sub, {})
        is_waf = pr.waf if pr else False
        if extras and not is_waf:
            port_str = ", ".join(f"{p}/{s}" for p, s in sorted(extras.items()))
            items.append((80, sub, f"Interesting + ports: {port_str} (score:{hit.score})"))

    # 4. Direct origins with interesting tech (no third-party, no WAF)
    for pr in all_probe_results:
        if not pr.live_urls or pr.waf:
            continue
        entry = entry_map.get(pr.subdomain, {})
        if entry.get("third_party"):
            continue
        if pr.technologies and pr.subdomain not in {i[1] for i in items}:
            tech_names = [t["name"] for t in pr.technologies[:3]]
            items.append((50, pr.subdomain, f"Direct origin: {', '.join(tech_names)}"))

    if not items:
        return

    items.sort(key=lambda x: -x[0])
    top = items[:10]

    console.print("\n[bold]Next Steps (top targets to investigate):[/]")
    for i, (_, sub, reason) in enumerate(top, 1):
        if "TAKEOVER" in reason:
            console.print(f"  [bold red]{i}. {sub}[/] -- {reason}")
        elif "High-value" in reason:
            console.print(f"  [bold yellow]{i}. {sub}[/] -- {reason}")
        else:
            console.print(f"  [cyan]{i}. {sub}[/] -- {reason}")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@app.command()
def run(
    input_file: Path = typer.Option(..., "-i", "--input", help="Path to domains file"),
    only_resolved: bool = typer.Option(False, "--only-resolved", help="Export only resolved subdomains in JSON"),
    sources: Optional[str] = typer.Option(None, "--sources", help="Comma-separated source names"),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to config YAML"),
    skip_probe: bool = typer.Option(False, "--skip-probe", help="Skip HTTP/HTTPS probing"),
    permutate: bool = typer.Option(False, "--permutate", help="Generate and resolve permutation candidates"),
    recursive: bool = typer.Option(False, "--recursive", help="Re-enumerate discovered sub-zones"),
    scan_ports: bool = typer.Option(False, "--scan-ports", help="Port scan resolved hosts"),
    diff: Optional[Path] = typer.Option(None, "--diff", help="Compare against a previous output directory"),
) -> None:
    """Enumerate subdomains for all domains in the input file."""
    _banner()
    cfg = load_settings(config)
    domains = _read_domains(input_file)
    only_sources = [s.strip() for s in sources.split(",")] if sources else None

    console.print(f"[bold]Targets:[/] {', '.join(domains)}")
    if only_sources:
        console.print(f"[bold]Sources:[/] {', '.join(only_sources)}")
    flags = []
    if permutate:
        flags.append("permutate")
    if recursive:
        flags.append("recursive")
    if scan_ports:
        flags.append("scan-ports")
    if skip_probe:
        flags.append("skip-probe")
    if diff:
        flags.append(f"diff={diff}")
    if flags:
        console.print(f"[bold]Flags:[/] {', '.join(flags)}")
    console.print()

    asyncio.run(_run_async(
        domains, cfg, only_sources, only_resolved,
        skip_probe, permutate, recursive, scan_ports,
        str(diff) if diff else None,
    ))


async def _run_async(
    domains: list[str],
    cfg: Settings,
    only_sources: list[str] | None,
    only_resolved: bool,
    skip_probe: bool,
    permutate: bool,
    recursive: bool,
    scan_ports: bool,
    diff_dir: str | None,
) -> None:
    t0 = time.time()
    all_entries: list[dict] = []
    source_counts: dict[str, dict[str, int]] = {}
    all_takeover: list[TakeoverCandidate] = []
    all_probe_results: list[ProbeResult] = []
    all_interesting: list[InterestingHit] = []
    all_port_results: list = []

    for domain in domains:
        console.rule(f"[bold]{domain}[/]")

        # --- Gather from all sources ---
        raw_results = await gather_subdomains(domain, cfg, only_sources)
        cleaned_map, unified = _clean_subdomains(raw_results, domain)

        source_counts[domain] = {src: len(subs) for src, subs in cleaned_map.items()}

        console.print(
            f"[bold green]{len(unified)}[/] unique subdomains from "
            f"{sum(1 for s in cleaned_map.values() if s)} sources"
        )

        if not unified:
            continue

        # --- Recursive enumeration: find sub-zones and re-enumerate ---
        if recursive:
            sub_zones = _find_sub_zones(unified, domain)
            if sub_zones:
                console.print(f"[dim]Recursive: enumerating {len(sub_zones)} valid sub-zones...[/]")
                _RECURSIVE_SOURCES = ["crtsh", "anubis", "rapiddns", "subfinder"]
                for i, sz in enumerate(sub_zones):
                    if i > 0:
                        await asyncio.sleep(2)
                    sz_results = await gather_subdomains(sz, cfg, _RECURSIVE_SOURCES)
                    sz_cleaned, sz_unified = _clean_subdomains(sz_results, domain)
                    new_found = sz_unified - unified
                    if new_found:
                        console.print(f"  [green]+{len(new_found)} from {sz}[/]")
                        unified |= new_found
                        for src, subs in sz_cleaned.items():
                            cleaned_map.setdefault(src, set()).update(subs & new_found)
                            source_counts[domain][src] = source_counts[domain].get(src, 0) + len(subs & new_found)

        # --- Wildcard detection ---
        wildcard_ips = await detect_wildcard(
            domain, cfg.dns_resolvers, cfg.dns_timeout
        )
        wcard_map = {domain: wildcard_ips} if wildcard_ips else {}

        # --- DNS resolution ---
        resolve_results = await resolve_batch(sorted(unified), cfg, wcard_map)

        # --- Permutation (if enabled, skip on wildcard domains) ---
        if permutate:
            if wildcard_ips:
                console.print(
                    "[yellow]Skipping permutations — wildcard DNS makes them unreliable[/]"
                )
            else:
                perm_candidates = generate_permutations(unified, domain)
                if perm_candidates:
                    valid_perms = {p for p in perm_candidates if _DOMAIN_RE.match(p)}
                    if valid_perms:
                        console.print(f"[dim]Resolving {len(valid_perms)} permutations...[/]")
                        perm_results = await resolve_batch(sorted(valid_perms), cfg, wcard_map)
                        perm_found = [r for r in perm_results if r.resolved]
                        if perm_found:
                            console.print(f"[bold green]+{len(perm_found)} new subdomains from permutations[/]")
                            resolve_results.extend(perm_found)
                            for pr in perm_found:
                                cleaned_map.setdefault("permutation", set()).add(pr.subdomain)
                            source_counts[domain]["permutation"] = len(perm_found)

        # --- Build entries ---
        entries = build_entries(resolve_results, cleaned_map, domain)
        all_entries.extend(entries)

        # --- CNAME takeover check ---
        candidates = check_takeover(entries)
        all_takeover.extend(candidates)

        # --- Interesting subdomain tagging ---
        resolved_names = [e["subdomain"] for e in entries if e["resolved"]]
        interesting = tag_interesting(resolved_names)
        all_interesting.extend(interesting)
        if interesting:
            console.print(f"[bold yellow]{len(interesting)} interesting targets found[/]")
            for hit in interesting[:5]:
                console.print(f"  [yellow]{hit.subdomain}[/] (score:{hit.score}) {hit.reason}")
            if len(interesting) > 5:
                console.print(f"  [dim]... and {len(interesting) - 5} more[/]")

    elapsed = time.time() - t0

    if not all_entries:
        console.print("[bold red]No subdomains found.[/]")
        raise typer.Exit(0)

    # --- HTTP probing (unless skipped) ---
    if not skip_probe:
        resolved_subs = [e["subdomain"] for e in all_entries if e["resolved"]]
        if resolved_subs:
            all_probe_results = await probe_batch(resolved_subs, cfg)
            live_count = sum(1 for p in all_probe_results if p.live_urls)
            console.print(f"[bold cyan]{live_count}[/] live HTTP hosts detected")

    # --- Port scanning (if enabled) ---
    if scan_ports:
        resolved_subs = [e["subdomain"] for e in all_entries if e["resolved"]]
        if resolved_subs:
            all_port_results = await port_scan_batch(resolved_subs, cfg)

    # --- Export everything ---
    out_dir = export_all(
        all_entries, source_counts, elapsed,
        only_resolved=only_resolved,
        diff_dir=diff_dir,
        takeover_candidates=all_takeover,
        probe_results=all_probe_results if all_probe_results else None,
        interesting_hits=all_interesting if all_interesting else None,
        port_results=all_port_results if all_port_results else None,
    )

    live_count = sum(1 for p in all_probe_results if p.live_urls) if all_probe_results else 0
    tech_count = sum(1 for p in all_probe_results if p.technologies) if all_probe_results else 0
    port_hosts = sum(1 for r in all_port_results if any(p not in (80, 443) for p in r.open_ports)) if all_port_results else 0
    all_hv_techs: list[str] = []
    for p in all_probe_results:
        all_hv_techs.extend(p.high_value_techs)

    waf_count = sum(1 for p in all_probe_results if p.waf) if all_probe_results else 0
    nowaf_live = sum(1 for p in all_probe_results if p.live_urls and not p.waf) if all_probe_results else 0
    third_party_count = sum(1 for e in all_entries if e.get("third_party")) if all_entries else 0

    _print_summary(
        all_entries, source_counts, len(all_takeover), live_count,
        len(all_interesting), tech_count, port_hosts,
        waf_count=waf_count,
        nowaf_live=nowaf_live,
        third_party_count=third_party_count,
    )

    _print_action_items(
        all_entries, all_takeover, all_probe_results,
        all_interesting, all_port_results,
    )
    console.print(f"\n[dim]Completed in {elapsed:.1f}s[/]\n")

    # --- Diff info for notifications ---
    new_subs: list[str] | None = None
    if diff_dir:
        diff_file = out_dir / "diff.json"
        if diff_file.is_file():
            import json
            diff_data = json.loads(diff_file.read_text())
            new_subs = diff_data.get("new_subdomains")

    # --- Send webhook notification ---
    await notify_results(
        total_subs=len(all_entries),
        resolved=sum(1 for e in all_entries if e["resolved"]),
        live=live_count,
        takeover_count=len(all_takeover),
        new_subs=new_subs,
        high_value=all_hv_techs if all_hv_techs else None,
        domains=list({e["root_domain"] for e in all_entries}),
    )


def _find_sub_zones(subdomains: set[str], root_domain: str) -> list[str]:
    """Find intermediate sub-zones worth re-enumerating.

    A sub-zone is valid when it appears in the discovered set itself,
    meaning sources confirmed its existence (e.g. we found both
    `internal.example.com` AND `a.internal.example.com`).  This avoids
    fabricating garbage zones from mangled hostnames.
    """
    suffix = f".{root_domain}"
    zone_children: dict[str, int] = {}

    for sub in subdomains:
        if not sub.endswith(suffix):
            continue
        prefix = sub[:-len(suffix)]
        parts = prefix.split(".")
        if len(parts) >= 2:
            zone = ".".join(parts[1:]) + suffix
            if zone != root_domain:
                zone_children[zone] = zone_children.get(zone, 0) + 1

    # Only keep zones that were also discovered as real subdomains
    # and have at least 2 children (to be worth re-enumerating)
    valid = [
        z for z, count in zone_children.items()
        if z in subdomains and count >= 2
        and all(len(lbl) <= 20 for lbl in z.split("."))
    ]
    return sorted(valid)[:15]


@app.command(name="diff")
def diff_cmd(
    old_dir: Path = typer.Argument(..., help="Path to older output directory"),
    new_dir: Path = typer.Argument(..., help="Path to newer output directory"),
) -> None:
    """Compare two previous scan results."""
    _banner()
    result = standalone_diff(old_dir, new_dir)
    if result:
        out_path = new_dir / "diff.json"
        import json
        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        console.print(f"\n[green]Diff saved to {out_path}[/]")


@app.command()
def doctor(
    config: Optional[Path] = typer.Option(None, "--config", help="Path to config YAML"),
) -> None:
    """Check availability of external tools and API keys."""
    _banner()
    cfg = load_settings(config)

    table = Table(title="Doctor Check", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Status")

    for name in ("subfinder", "amass"):
        binary_path = cfg.source(name).path or name
        found = shutil.which(binary_path)
        if found:
            table.add_row(f"{name} binary", f"[green]OK[/] ({found})")
        else:
            table.add_row(f"{name} binary", "[yellow]NOT FOUND[/]")

    for label, val in [
        ("VirusTotal API key", cfg.virustotal_key),
        ("urlscan API key", cfg.urlscan_key),
    ]:
        if val:
            masked = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
            table.add_row(label, f"[green]SET[/] ({masked})")
        else:
            table.add_row(label, "[yellow]NOT SET[/]")

    free_sources = ["crtsh", "alienvault", "hackertarget", "wayback", "rapiddns", "anubis"]
    enabled = [s for s in free_sources if cfg.source(s).enabled]
    table.add_row("Free sources (no key)", f"[green]{len(enabled)} enabled[/] ({', '.join(enabled)})")

    import os
    webhook = os.getenv("WEBHOOK_URL", "")
    if webhook:
        table.add_row("Webhook", f"[green]SET[/] ({webhook[:30]}...)")
    else:
        table.add_row("Webhook", "[yellow]NOT SET[/]")

    resolver_str = ", ".join(cfg.dns_resolvers)
    table.add_row("DNS resolvers", f"[green]{resolver_str}[/]")

    console.print(table)

    console.print("\n[bold]Capabilities:[/]")
    console.print("  [green]✓[/] Technology fingerprinting (auto)")
    console.print("  [green]✓[/] WAF detection (auto)")
    console.print("  [green]✓[/] Third-party / CDN detection (auto)")
    console.print("  [green]✓[/] Interesting target tagging (auto)")
    console.print("  [green]✓[/] Port scanning (--scan-ports)")
    console.print("  [green]✓[/] Recursive enumeration (--recursive)")
    console.print("  [green]✓[/] Webhook notifications (WEBHOOK_URL)")
    console.print("  [green]✓[/] Offensive output (httpx_output.jsonl, nowaf_targets.txt, commands.txt)")


@app.command()
def version() -> None:
    """Print the version and exit."""
    console.print(f"subenum v{__version__}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
