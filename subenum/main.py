"""subenum — Passive subdomain enumeration CLI for Bug Bounty.

Usage:
    python -m subenum.main run -i domains.txt
    python -m subenum.main run -i domains.txt --permutate --scan-ports
    python -m subenum.main run -i domains.txt --recursive --skip-probe
    python -m subenum.main run -i domains.txt --bruteforce --wordlist /path/to/words.txt
    python -m subenum.main run -i domains.txt --permutate --wordlist /path/to/words.txt
    python -m subenum.main run -i domains.txt --resume output/20260514_123456
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
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from subenum import __version__
from subenum.bruteforce import bruteforce_domain, load_wordlist
from subenum.checkpoint import CheckpointManager
from subenum.js_extract import run_js_extraction, write_js_output, JSHostResult
from subenum.config import Settings, load_settings
from subenum.dns_utils import detect_wildcard, resolve_batch, ResolveResult
from subenum.exporters import build_entries, export_all, standalone_diff
from subenum.http_probe import probe_batch, ProbeResult
from subenum.headers_audit import audit_headers, print_headers_summary, export_headers_audit
from subenum.shodan_enrich import enrich_with_shodan, export_shodan
from subenum.interesting import tag_interesting, enrich_with_probe, InterestingHit
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
            # Reject garbage: prefix must be max 6 labels deep, each ≤40 chars
            prefix = s[: -len(suffix)]
            labels = prefix.split(".")
            if len(labels) > 6:
                continue
            if any(len(lbl) > 40 for lbl in labels):
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
        # Only show sources that returned at least one subdomain across all domains
        all_src_names = sorted({
            s for d in source_counts.values() for s, n in d.items() if n > 0
        })
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

    # 4. High-score interesting targets (≥7) not already listed
    already_added = {i[1] for i in items}
    for sub, hit in sorted(interesting_set.items(), key=lambda x: -x[1].score):
        if sub in already_added or hit.score < 7:
            continue
        pr = probe_map.get(sub)
        waf_note = f" [WAF]" if pr and pr.waf else ""
        items.append((55 + hit.score, sub, f"score:{hit.score}{waf_note} — {hit.reason}"))

    # 5. Direct origins with interesting tech (no third-party, no WAF)
    already_added = {i[1] for i in items}
    for pr in all_probe_results:
        if not pr.live_urls or pr.waf:
            continue
        entry = entry_map.get(pr.subdomain, {})
        if entry.get("third_party"):
            continue
        if pr.technologies and pr.subdomain not in already_added:
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
    bruteforce: bool = typer.Option(False, "--bruteforce", help="DNS brute-force using --wordlist"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Wordlist for --bruteforce and/or --permutate"),
    resume: Optional[Path] = typer.Option(None, "--resume", help="Resume interrupted run from its output directory"),
    js: bool = typer.Option(False, "--js", help="Extract endpoints, subdomains and secrets from JS assets"),
    nuclei: bool = typer.Option(False, "--nuclei", help="Run nuclei on nuclei_targets.txt after the scan"),
    nuclei_severity: str = typer.Option("medium,high,critical", "--nuclei-severity", help="Nuclei severity filter"),
    shodan: bool = typer.Option(False, "--shodan", help="Enrich resolved IPs with Shodan data (requires SHODAN_API_KEY)"),
) -> None:
    """Enumerate subdomains for all domains in the input file."""
    _banner()
    cfg = load_settings(config)
    domains = _read_domains(input_file)
    only_sources = [s.strip() for s in sources.split(",")] if sources else None

    # Validate + load wordlist once here so errors surface before the run starts
    words: list[str] = []
    if wordlist:
        if not wordlist.is_file():
            console.print(f"[bold red]Wordlist not found: {wordlist}[/]")
            raise typer.Exit(1)
        words = load_wordlist(wordlist)
        console.print(f"[dim]Wordlist: {len(words)} words loaded from {wordlist}[/]")

    if bruteforce and not words:
        console.print("[bold red]--bruteforce requires --wordlist[/]")
        raise typer.Exit(1)

    if js and skip_probe:
        console.print("[bold red]--js requires HTTP probing; remove --skip-probe[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Targets:[/] {', '.join(domains)}")
    if only_sources:
        console.print(f"[bold]Sources:[/] {', '.join(only_sources)}")
    flags = []
    if permutate:
        flags.append("permutate" + (f"+wordlist({len(words)}w)" if words else ""))
    if bruteforce:
        flags.append(f"bruteforce({len(words)}w)")
    if recursive:
        flags.append("recursive")
    if scan_ports:
        flags.append("scan-ports")
    if skip_probe:
        flags.append("skip-probe")
    if js:
        flags.append("js-extract")
    if nuclei:
        flags.append(f"nuclei({nuclei_severity})")
    if shodan:
        flags.append("shodan")
    if resume:
        flags.append(f"resume={resume}")
    if diff:
        flags.append(f"diff={diff}")
    if flags:
        console.print(f"[bold]Flags:[/] {', '.join(flags)}")
    console.print()

    asyncio.run(_run_async(
        domains, cfg, only_sources, only_resolved,
        skip_probe, permutate, recursive, scan_ports,
        str(diff) if diff else None,
        words, bruteforce, resume, js,
        nuclei, nuclei_severity, shodan,
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
    words: list[str],
    do_bruteforce: bool,
    resume_dir: Optional[Path],
    do_js: bool,
    do_nuclei: bool = False,
    nuclei_severity: str = "medium,high,critical",
    do_shodan: bool = False,
) -> None:
    t0 = time.time()
    all_entries: list[dict] = []
    source_counts: dict[str, dict[str, int]] = {}
    all_takeover: list[TakeoverCandidate] = []
    all_probe_results: list[ProbeResult] = []
    all_interesting: list[InterestingHit] = []
    all_port_results: list = []

    # ------------------------------------------------------------------
    # Set up run directory and checkpoint early so we can save state
    # as each domain completes.
    # ------------------------------------------------------------------
    if resume_dir is not None:
        if not resume_dir.is_dir():
            console.print(f"[bold red]Resume directory not found: {resume_dir}[/]")
            raise typer.Exit(1)
        run_dir = resume_dir
        console.print(f"[bold cyan]Resuming run in {run_dir}[/]")
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = Path("output") / ts
        run_dir.mkdir(parents=True, exist_ok=True)

    ckpt = CheckpointManager(run_dir / ".checkpoint.json")

    # Words for permutations: cap at _MAX_PERM_WORDS so combinatorics stay
    # reasonable; the full list is used unchanged for flat brute-force.
    from subenum.permutations import _MAX_PERM_WORDS
    perm_words: list[str] | None = words[:_MAX_PERM_WORDS] if words else None

    for domain in domains:
        console.rule(f"[bold]{domain}[/]")

        # ------------------------------------------------------------------
        # Fast-path: load completed domain from checkpoint
        # ------------------------------------------------------------------
        if ckpt.is_domain_done(domain):
            console.print(f"[dim]{domain} — already complete, loading from checkpoint[/]")
            saved = ckpt.get_domain(domain)
            all_entries.extend(saved["entries"])
            source_counts.update({domain: saved["source_counts"]})
            all_takeover.extend(TakeoverCandidate(**c) for c in saved["takeover_candidates"])
            all_interesting.extend(InterestingHit(**h) for h in saved["interesting_hits"])
            continue

        # --- Gather from all sources ---
        raw_results = await gather_subdomains(domain, cfg, only_sources)
        cleaned_map, unified = _clean_subdomains(raw_results, domain)

        source_counts[domain] = {src: len(subs) for src, subs in cleaned_map.items()}

        console.print(
            f"[bold green]{len(unified)}[/] unique subdomains from "
            f"{sum(1 for s in cleaned_map.values() if s)} sources"
        )

        if not unified:
            ckpt.save_domain(domain, [], {}, [], [])
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
        wildcard_ips = await detect_wildcard(domain, cfg.dns_resolvers, cfg.dns_timeout)
        wcard_map = {domain: wildcard_ips} if wildcard_ips else {}

        # --- DNS resolution ---
        resolve_results = await resolve_batch(sorted(unified), cfg, wcard_map)

        # --- Permutation (skip on wildcard domains) ---
        if permutate:
            if wildcard_ips:
                console.print("[yellow]Skipping permutations — wildcard DNS makes them unreliable[/]")
            else:
                perm_candidates = generate_permutations(unified, domain, extra_words=perm_words)
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

        # --- DNS brute-force ---
        if do_bruteforce:
            if wildcard_ips:
                console.print("[yellow]Skipping brute-force — wildcard DNS makes results unreliable[/]")
            else:
                known = {r.subdomain for r in resolve_results}
                bf_results = await bruteforce_domain(domain, words, cfg, wildcard_ips, known)
                if bf_results:
                    console.print(f"[bold green]+{len(bf_results)} new subdomains from brute-force[/]")
                    resolve_results.extend(bf_results)
                    for r in bf_results:
                        cleaned_map.setdefault("bruteforce", set()).add(r.subdomain)
                    source_counts[domain]["bruteforce"] = len(bf_results)

        # --- Build entries ---
        entries = build_entries(resolve_results, cleaned_map, domain)

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

        # --- Checkpoint: persist this domain so a resume can skip it ---
        ckpt.save_domain(
            domain, entries, source_counts[domain], candidates, interesting
        )
        all_entries.extend(entries)

    elapsed = time.time() - t0

    if not all_entries:
        console.print("[bold red]No subdomains found.[/]")
        raise typer.Exit(0)

    # --- HTTP probing (unless skipped) ---
    if not skip_probe:
        if ckpt.probe_done:
            console.print("[dim]HTTP probe already done — loading from checkpoint[/]")
            saved_probe = ckpt.load_probe()
            if saved_probe:
                all_probe_results = [ProbeResult(**p) for p in saved_probe]
        else:
            resolved_subs = [e["subdomain"] for e in all_entries if e["resolved"]]
            if resolved_subs:
                all_probe_results = await probe_batch(resolved_subs, cfg)
                ckpt.save_probe(all_probe_results)

        live_count = sum(1 for p in all_probe_results if p.live_urls)
        if live_count:
            console.print(f"[bold cyan]{live_count}[/] live HTTP hosts detected")

    # --- JS extraction (if enabled) ---
    all_js_results: list[JSHostResult] = []
    if do_js and all_probe_results:
        root_domains = {e["root_domain"] for e in all_entries}
        all_js_results = await run_js_extraction(all_probe_results, root_domains, cfg)
        if all_js_results:
            # Surface any new subdomains found in JS files into interesting hits
            js_new_subs: set[str] = set()
            for hr in all_js_results:
                js_new_subs.update(hr.all_subdomains)
            known_subs = {e["subdomain"] for e in all_entries}
            discovered_in_js = js_new_subs - known_subs
            if discovered_in_js:
                console.print(
                    f"[bold yellow]{len(discovered_in_js)} new subdomain ref(s) in JS "
                    f"— check js_subdomains.txt[/]"
                )

    # --- Port scanning (if enabled) ---
    if scan_ports:
        resolved_subs = [e["subdomain"] for e in all_entries if e["resolved"]]
        if resolved_subs:
            all_port_results = await port_scan_batch(resolved_subs, cfg)

    # --- Shodan enrichment ---
    shodan_results: dict = {}
    if do_shodan:
        if not cfg.shodan_key:
            console.print("[yellow]--shodan requires SHODAN_API_KEY to be set[/]")
        else:
            shodan_results = await enrich_with_shodan(all_entries, cfg)

    # --- Enrich interesting scores with HTTP probe data ---
    if all_probe_results and all_interesting:
        enrich_with_probe(all_interesting, all_probe_results)

    # --- Security headers audit ---
    all_header_findings = []
    if all_probe_results:
        all_header_findings = audit_headers(all_probe_results)
        print_headers_summary(all_header_findings)

    # --- Export everything ---
    export_all(
        all_entries, source_counts, elapsed,
        only_resolved=only_resolved,
        output_dir=run_dir,
        diff_dir=diff_dir,
        takeover_candidates=all_takeover,
        probe_results=all_probe_results if all_probe_results else None,
        interesting_hits=all_interesting if all_interesting else None,
        port_results=all_port_results if all_port_results else None,
    )
    if all_js_results:
        write_js_output(all_js_results, run_dir)
    if all_header_findings:
        export_headers_audit(all_header_findings, run_dir)
    if shodan_results:
        export_shodan(shodan_results, all_entries, run_dir)

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

    # --- Nuclei auto-trigger ---
    if do_nuclei:
        await _run_nuclei(run_dir, nuclei_severity)

    # --- Diff info for notifications ---
    new_subs: list[str] | None = None
    if diff_dir:
        diff_file = run_dir / "diff.json"
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


async def _run_nuclei(run_dir: Path, severity: str) -> None:
    """Execute nuclei with real-time progress display."""
    targets_file = run_dir / "nuclei_targets.txt"
    if not targets_file.is_file() or targets_file.stat().st_size == 0:
        console.print("[yellow]--nuclei: no targets file found, skipping[/]")
        return

    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        console.print("[yellow]--nuclei: nuclei binary not found in PATH, skipping[/]")
        return

    target_count = sum(1 for ln in targets_file.read_text().splitlines() if ln.strip())
    output_file = run_dir / "nuclei_results.txt"

    cmd = [
        nuclei_bin,
        "-l", str(targets_file),
        "-severity", severity,
        "-o", str(output_file),
        "-stats", "-stats-interval", "5",
    ]
    console.print(
        f"\n[bold magenta]Running nuclei[/] — {target_count} targets | severity: {severity}"
    )

    findings: list[str] = []
    _progress = {"requests": "starting…"}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _drain_stdout() -> None:
            assert proc.stdout
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").strip()
                if line:
                    findings.append(line)

        async def _drain_stderr() -> None:
            assert proc.stderr
            async for raw in proc.stderr:
                line = raw.decode(errors="replace").strip()
                # Nuclei stats line: "... | Requests: 1234/394765 | ..."
                m = re.search(r"Requests:\s*([\d,]+)/([\d,]+)", line, re.I)
                if m:
                    done_n = int(m.group(1).replace(",", ""))
                    total_n = int(m.group(2).replace(",", ""))
                    pct = done_n / total_n * 100 if total_n else 0
                    _progress["requests"] = f"{done_n:,}/{total_n:,}  ({pct:.0f}%)"

        async def _update_live(live: Live) -> None:
            _SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            i = 0
            while proc.returncode is None:
                spin = _SPIN[i % len(_SPIN)]
                color = "red" if findings else "cyan"
                live.update(Text.from_markup(
                    f"[bold magenta]{spin} nuclei[/]  "
                    f"[dim]requests:[/] {_progress['requests']}  "
                    f"[dim]findings:[/] [bold {color}]{len(findings)}[/]"
                ))
                i += 1
                await asyncio.sleep(0.4)
            live.update(Text.from_markup(
                f"[bold green]✓ nuclei done[/]  "
                f"[dim]findings:[/] [bold {'red' if findings else 'green'}]{len(findings)}[/]"
            ))

        with Live(console=console, refresh_per_second=4) as live:
            await asyncio.gather(
                _drain_stdout(),
                _drain_stderr(),
                _update_live(live),
                proc.wait(),
            )

        if proc.returncode not in (0, None) and not findings:
            console.print(f"[yellow]nuclei exited {proc.returncode}[/]")

        if findings:
            console.print(
                f"\n[bold red]nuclei: {len(findings)} finding(s)[/] — {output_file.name}"
            )
            for ln in findings[:10]:
                console.print(f"  [red]{ln}[/]")
            if len(findings) > 10:
                console.print(f"  [dim]... and {len(findings) - 10} more[/]")
        else:
            console.print("[green]nuclei: no findings[/]")

    except Exception as exc:
        console.print(f"[yellow]nuclei failed: {exc}[/]")


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

    for name in ("subfinder", "amass", "nuclei"):
        binary_path = cfg.source(name).path if name in ("subfinder", "amass") else name
        found = shutil.which(binary_path or name)
        if found:
            table.add_row(f"{name} binary", f"[green]OK[/] ({found})")
        else:
            table.add_row(f"{name} binary", "[yellow]NOT FOUND[/]")

    for label, val in [
        ("VirusTotal API key", cfg.virustotal_key),
        ("urlscan API key", cfg.urlscan_key),
        ("Chaos API key", cfg.chaos_key),
        ("GitHub token", cfg.github_token),
        ("Shodan API key", cfg.shodan_key),
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
# wordlist sub-app
# ---------------------------------------------------------------------------

wordlist_app = typer.Typer(
    name="wordlist",
    help="Wordlist management: stats, merge, and target-specific generation.",
    add_completion=False,
)
app.add_typer(wordlist_app, name="wordlist")


def _load_words_from_file(path: Path) -> list[str]:
    """Read non-blank, non-comment words from a wordlist file."""
    words = []
    for line in path.read_text(errors="replace").splitlines():
        w = line.strip().lower()
        if w and not w.startswith("#"):
            words.append(w)
    return words


@wordlist_app.command("stats")
def wordlist_stats(
    file: Path = typer.Argument(..., help="Path to wordlist file"),
) -> None:
    """Show word count, category breakdown, and duplicate analysis."""
    if not file.is_file():
        console.print(f"[red]File not found: {file}[/]")
        raise typer.Exit(1)

    lines = file.read_text(errors="replace").splitlines()
    words: list[str] = []
    categories: list[tuple[str, list[str]]] = []
    current_category = "Uncategorized"
    current_words: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# ---"):
            # Save previous category
            if current_words:
                categories.append((current_category, current_words[:]))
                current_words = []
            current_category = stripped.lstrip("# -").strip()
        elif stripped and not stripped.startswith("#"):
            w = stripped.lower()
            words.append(w)
            current_words.append(w)

    if current_words:
        categories.append((current_category, current_words[:]))

    seen: dict[str, int] = {}
    for w in words:
        seen[w] = seen.get(w, 0) + 1
    duplicates = {w: c for w, c in seen.items() if c > 1}

    console.print(f"\n[bold]Wordlist stats:[/] {file.name}")
    console.print(f"  Total lines : {len(lines)}")
    console.print(f"  Words       : [bold cyan]{len(words)}[/]")
    console.print(f"  Unique      : [bold green]{len(seen)}[/]")

    if duplicates:
        console.print(f"  [bold red]Duplicates  : {len(duplicates)}[/]")
        for w, c in sorted(duplicates.items(), key=lambda x: -x[1])[:10]:
            console.print(f"    [red]{w!r}[/] appears {c}×")
    else:
        console.print("  Duplicates  : [green]none[/]")

    if categories:
        table = Table(title="Categories", show_lines=False)
        table.add_column("Category", style="bold")
        table.add_column("Words", justify="right")
        for cat, cat_words in categories:
            table.add_row(cat, str(len(cat_words)))
        console.print(table)


@wordlist_app.command("merge")
def wordlist_merge(
    files: list[Path] = typer.Argument(..., help="Wordlist files to merge"),
    output: Path = typer.Option(..., "-o", "--output", help="Output file path"),
    no_sort: bool = typer.Option(False, "--no-sort", help="Skip alphabetical sort"),
) -> None:
    """Merge multiple wordlists, deduplicate, and write to output."""
    merged: dict[str, None] = {}  # ordered set via insertion-order dict
    for path in files:
        if not path.is_file():
            console.print(f"[yellow]Skipping missing file: {path}[/]")
            continue
        for word in _load_words_from_file(path):
            merged[word] = None
        console.print(f"[dim]Loaded {path.name}[/]")

    result = list(merged.keys())
    if not no_sort:
        result.sort()

    header = (
        f"# Merged wordlist — {len(result)} unique words\n"
        f"# Sources: {', '.join(f.name for f in files)}\n"
    )
    output.write_text(header + "\n".join(result) + "\n")
    console.print(
        f"[green]Merged {len(files)} file(s) → [bold]{len(result)}[/] unique words → {output}[/]"
    )


@wordlist_app.command("generate")
def wordlist_generate(
    scan_dir: Path = typer.Argument(..., help="Previous scan output directory"),
    output: Path = typer.Option(..., "-o", "--output", help="Output wordlist file"),
    base_wordlist: Optional[Path] = typer.Option(
        None, "--base", help="Optional base wordlist to seed results with"
    ),
    max_words: int = typer.Option(5000, "--max", help="Maximum words to emit"),
) -> None:
    """Generate a target-specific wordlist from a previous scan's subdomains.json.

    Extracts all subdomain labels, adds numeric/version mutations, then merges
    with an optional base wordlist and deduplicates.
    """
    import json
    from subenum.permutations import _number_variants, _version_variants

    subs_file = scan_dir / "subdomains.json"
    if not subs_file.is_file():
        console.print(f"[red]subdomains.json not found in {scan_dir}[/]")
        raise typer.Exit(1)

    data = json.loads(subs_file.read_text())
    subdomains: list[str] = [e["subdomain"] for e in data if isinstance(e, dict) and e.get("subdomain")]

    # Extract first-level labels
    labels: set[str] = set()
    for sub in subdomains:
        parts = sub.split(".")
        if len(parts) >= 3:
            labels.add(parts[0])

    # Collect label + mutations
    generated: set[str] = set(labels)
    for label in labels:
        for v in _version_variants(label):
            generated.add(v)
        for v in _number_variants(label):
            generated.add(v)

    # Merge with optional base wordlist
    if base_wordlist and base_wordlist.is_file():
        for w in _load_words_from_file(base_wordlist):
            generated.add(w)

    result = sorted(generated)[:max_words]

    header = (
        f"# Target-specific wordlist generated from {scan_dir.name}\n"
        f"# Labels extracted: {len(labels)}, total words: {len(result)}\n"
    )
    output.write_text(header + "\n".join(result) + "\n")
    console.print(
        f"[green]Generated [bold]{len(result)}[/] words from {len(subdomains)} subdomains → {output}[/]"
    )
    if labels:
        sample = sorted(labels)[:8]
        console.print(f"[dim]Sample labels: {', '.join(sample)}[/]")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
