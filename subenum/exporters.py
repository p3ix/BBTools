"""Export enumeration results to txt, json, csv, stats and diff files."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from subenum.dns_utils import ResolveResult

console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Build structured entries
# ---------------------------------------------------------------------------

def build_entries(
    resolve_results: list[ResolveResult],
    source_map: dict[str, set[str]],
    root_domain: str,
) -> list[dict[str, Any]]:
    """Merge DNS results with source information into export-ready dicts."""

    sub_sources: dict[str, list[str]] = {}
    for source_name, subs in source_map.items():
        for s in subs:
            sub_sources.setdefault(s, []).append(source_name)

    entries: list[dict[str, Any]] = []
    for r in resolve_results:
        entries.append({
            "root_domain": root_domain,
            "subdomain": r.subdomain,
            "sources": sorted(sub_sources.get(r.subdomain, [])),
            "resolved": r.resolved,
            "a_records": r.a_records,
            "aaaa_records": r.aaaa_records,
            "cname_records": r.cname_records,
        })
    return entries


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def build_stats(
    all_entries: list[dict[str, Any]],
    source_counts: dict[str, dict[str, int]],
    elapsed: float,
    **extra: Any,
) -> dict[str, Any]:
    total = len(all_entries)
    resolved = sum(1 for e in all_entries if e["resolved"])

    per_domain: dict[str, dict[str, int]] = {}
    for e in all_entries:
        rd = e["root_domain"]
        per_domain.setdefault(rd, {"total": 0, "resolved": 0})
        per_domain[rd]["total"] += 1
        if e["resolved"]:
            per_domain[rd]["resolved"] += 1

    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "total_subdomains": total,
        "resolved_subdomains": resolved,
        "unresolved_subdomains": total - resolved,
        "per_domain": per_domain,
        "per_source": source_counts,
    }
    stats.update(extra)
    return stats


# ---------------------------------------------------------------------------
# Diff against a previous run
# ---------------------------------------------------------------------------

def compute_diff(
    current_entries: list[dict[str, Any]],
    previous_dir: str | Path,
) -> dict[str, Any]:
    prev = Path(previous_dir)
    prev_all_path = prev / "all_subdomains.txt"
    prev_resolved_path = prev / "resolved_subdomains.txt"

    if not prev_all_path.is_file():
        console.print(f"[yellow]Previous all_subdomains.txt not found in {prev}[/]")
        return {}

    prev_all = {l.strip() for l in prev_all_path.read_text().splitlines() if l.strip()}
    prev_resolved: set[str] = set()
    if prev_resolved_path.is_file():
        prev_resolved = {
            l.strip() for l in prev_resolved_path.read_text().splitlines() if l.strip()
        }

    cur_all = {e["subdomain"] for e in current_entries}
    cur_resolved = {e["subdomain"] for e in current_entries if e["resolved"]}

    new_subs = sorted(cur_all - prev_all)
    removed_subs = sorted(prev_all - cur_all)
    newly_resolved = sorted(cur_resolved - prev_resolved)
    newly_unresolved = sorted(prev_resolved - cur_resolved)

    diff = {
        "compared_to": str(prev),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "newly_resolved": newly_resolved,
        "newly_unresolved": newly_unresolved,
        "new_count": len(new_subs),
        "removed_count": len(removed_subs),
    }

    if new_subs:
        console.print(f"\n[bold green]+{len(new_subs)} NEW subdomains[/]")
        for s in new_subs[:20]:
            console.print(f"  [green]+ {s}[/]")
        if len(new_subs) > 20:
            console.print(f"  [dim]... and {len(new_subs) - 20} more[/]")
    if removed_subs:
        console.print(f"[bold red]-{len(removed_subs)} REMOVED subdomains[/]")
    if newly_resolved:
        console.print(f"[bold cyan]{len(newly_resolved)} newly resolved[/]")

    return diff


def standalone_diff(dir_old: Path, dir_new: Path) -> dict[str, Any]:
    """Diff two previous run directories without running a new scan."""
    old_all_path = dir_old / "all_subdomains.txt"
    new_all_path = dir_new / "all_subdomains.txt"
    old_res_path = dir_old / "resolved_subdomains.txt"
    new_res_path = dir_new / "resolved_subdomains.txt"

    for p in (old_all_path, new_all_path):
        if not p.is_file():
            console.print(f"[bold red]{p} not found[/]")
            return {}

    old_all = {l.strip() for l in old_all_path.read_text().splitlines() if l.strip()}
    new_all = {l.strip() for l in new_all_path.read_text().splitlines() if l.strip()}
    old_res = {l.strip() for l in old_res_path.read_text().splitlines() if l.strip()} if old_res_path.is_file() else set()
    new_res = {l.strip() for l in new_res_path.read_text().splitlines() if l.strip()} if new_res_path.is_file() else set()

    new_subs = sorted(new_all - old_all)
    removed_subs = sorted(old_all - new_all)
    newly_resolved = sorted(new_res - old_res)
    newly_unresolved = sorted(old_res - new_res)

    diff = {
        "old_dir": str(dir_old),
        "new_dir": str(dir_new),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "newly_resolved": newly_resolved,
        "newly_unresolved": newly_unresolved,
        "new_count": len(new_subs),
        "removed_count": len(removed_subs),
    }

    table = Table(title="Diff Summary", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("New subdomains", f"[green]+{len(new_subs)}[/]")
    table.add_row("Removed subdomains", f"[red]-{len(removed_subs)}[/]")
    table.add_row("Newly resolved", f"[cyan]{len(newly_resolved)}[/]")
    table.add_row("Newly unresolved", f"[yellow]{len(newly_unresolved)}[/]")
    console.print(table)

    if new_subs:
        console.print("\n[bold green]New subdomains:[/]")
        for s in new_subs[:30]:
            console.print(f"  [green]+ {s}[/]")
        if len(new_subs) > 30:
            console.print(f"  [dim]... and {len(new_subs) - 30} more[/]")

    return diff


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------

def export_all(
    all_entries: list[dict[str, Any]],
    source_counts: dict[str, dict[str, int]],
    elapsed: float,
    only_resolved: bool = False,
    output_base: str | Path = "output",
    diff_dir: str | Path | None = None,
    takeover_candidates: list | None = None,
    probe_results: list | None = None,
    interesting_hits: list | None = None,
    port_results: list | None = None,
) -> Path:
    """Write all output files and return the output directory path."""

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(output_base) / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    all_subs = sorted({e["subdomain"] for e in all_entries})
    resolved_subs = sorted({e["subdomain"] for e in all_entries if e["resolved"]})

    # --- Core text files ---
    (out_dir / "all_subdomains.txt").write_text("\n".join(all_subs) + "\n")
    (out_dir / "resolved_subdomains.txt").write_text("\n".join(resolved_subs) + "\n")

    # --- Merge HTTP probe data into entries ---
    if probe_results:
        probe_map = {p.subdomain: p for p in probe_results}
        for entry in all_entries:
            pr = probe_map.get(entry["subdomain"])
            if pr:
                entry["http_status"] = pr.http_status
                entry["https_status"] = pr.https_status
                entry["http_title"] = pr.http_title
                entry["http_redirect"] = pr.http_redirect
                entry["http_server"] = pr.http_server
                entry["http_content_length"] = pr.http_content_length
                entry["body_hash"] = pr.body_hash
                entry["cookies"] = pr.cookies
                entry["technologies"] = pr.technologies
                entry["high_value_techs"] = pr.high_value_techs

    # --- Merge takeover data into entries ---
    if takeover_candidates:
        takeover_map = {c.subdomain: c for c in takeover_candidates}
        for entry in all_entries:
            tc = takeover_map.get(entry["subdomain"])
            if tc:
                entry["takeover_candidate"] = True
                entry["takeover_service"] = tc.service
                entry["takeover_cname"] = tc.cname

    # --- Merge interesting data into entries ---
    if interesting_hits:
        interesting_map = {h.subdomain: h for h in interesting_hits}
        for entry in all_entries:
            hit = interesting_map.get(entry["subdomain"])
            if hit:
                entry["interesting"] = True
                entry["interesting_score"] = hit.score
                entry["interesting_tags"] = hit.tags
                entry["interesting_reason"] = hit.reason

    # --- Merge port scan data into entries ---
    if port_results:
        port_map = {r.host: r for r in port_results}
        for entry in all_entries:
            pr = port_map.get(entry["subdomain"])
            if pr and pr.open_ports:
                entry["open_ports"] = {
                    str(p): svc for p, svc in sorted(pr.open_ports.items())
                }

    # --- subdomains.json ---
    export_entries = [e for e in all_entries if e["resolved"]] if only_resolved else all_entries
    (out_dir / "subdomains.json").write_text(
        json.dumps(export_entries, indent=2, ensure_ascii=False) + "\n"
    )

    # --- stats.json ---
    extra_stats: dict[str, Any] = {}
    if interesting_hits:
        extra_stats["interesting_count"] = len(interesting_hits)
    if probe_results:
        extra_stats["live_hosts"] = sum(1 for p in probe_results if p.live_urls)
        all_techs: dict[str, int] = {}
        for p in probe_results:
            for t in p.technologies:
                all_techs[t["name"]] = all_techs.get(t["name"], 0) + 1
        extra_stats["technology_summary"] = dict(sorted(all_techs.items(), key=lambda x: -x[1]))
    if port_results:
        extra_stats["hosts_with_extra_ports"] = sum(
            1 for r in port_results if any(p not in (80, 443) for p in r.open_ports)
        )

    stats = build_stats(all_entries, source_counts, elapsed, **extra_stats)
    (out_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n"
    )

    # --- ips.txt (unique IPs for nmap/masscan) ---
    all_ips: set[str] = set()
    for e in all_entries:
        all_ips.update(e.get("a_records", []))
        all_ips.update(e.get("aaaa_records", []))
    if all_ips:
        (out_dir / "ips.txt").write_text("\n".join(sorted(all_ips)) + "\n")

    # --- scope.txt (Burp-style wildcard scope) ---
    root_domains = sorted({e["root_domain"] for e in all_entries})
    scope_lines = [f"*.{rd}" for rd in root_domains]
    (out_dir / "scope.txt").write_text("\n".join(scope_lines) + "\n")

    # --- live_hosts.txt (URLs from HTTP probing) ---
    if probe_results:
        live_urls: list[str] = []
        for pr in probe_results:
            live_urls.extend(pr.live_urls)
        if live_urls:
            (out_dir / "live_hosts.txt").write_text("\n".join(sorted(set(live_urls))) + "\n")

    # --- nuclei_targets.txt (one URL per line, ready for nuclei -l) ---
    if probe_results:
        nuclei_targets: list[str] = []
        for pr in probe_results:
            if pr.live_urls:
                nuclei_targets.append(pr.live_urls[0])  # prefer HTTPS
        if nuclei_targets:
            (out_dir / "nuclei_targets.txt").write_text("\n".join(sorted(nuclei_targets)) + "\n")

    # --- takeover_candidates.txt ---
    if takeover_candidates:
        lines = [f"{c.subdomain}\t{c.cname}\t{c.service}" for c in takeover_candidates]
        (out_dir / "takeover_candidates.txt").write_text("\n".join(lines) + "\n")

    # --- interesting.txt (prioritised by score) ---
    if interesting_hits:
        lines = []
        for h in interesting_hits:
            tag_str = ",".join(h.tags)
            lines.append(f"[{h.score:2d}] {h.subdomain}\t{tag_str}\t{h.reason}")
        (out_dir / "interesting.txt").write_text("\n".join(lines) + "\n")

    # --- technologies.json ---
    if probe_results:
        tech_data: dict[str, list[dict]] = {}
        for pr in probe_results:
            if pr.technologies:
                tech_data[pr.subdomain] = pr.technologies
        if tech_data:
            (out_dir / "technologies.json").write_text(
                json.dumps(tech_data, indent=2, ensure_ascii=False) + "\n"
            )

    # --- ports.json ---
    if port_results:
        port_data: dict[str, dict[str, str]] = {}
        for pr in port_results:
            if pr.open_ports:
                port_data[pr.host] = {str(p): svc for p, svc in sorted(pr.open_ports.items())}
        if port_data:
            (out_dir / "ports.json").write_text(
                json.dumps(port_data, indent=2, ensure_ascii=False) + "\n"
            )

    # --- subdomains.csv ---
    _export_csv(out_dir / "subdomains.csv", export_entries)

    # --- diff.json (if comparing against previous run) ---
    if diff_dir:
        diff_data = compute_diff(all_entries, diff_dir)
        if diff_data:
            (out_dir / "diff.json").write_text(
                json.dumps(diff_data, indent=2, ensure_ascii=False) + "\n"
            )

    console.print(f"\n[bold green]Results saved to {out_dir}/[/]")
    return out_dir


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "root_domain", "subdomain", "resolved",
    "a_records", "aaaa_records", "cname_records", "sources",
    "http_status", "https_status", "http_title", "http_server",
    "body_hash", "cookies",
    "takeover_candidate", "takeover_service",
    "interesting", "interesting_score", "interesting_tags",
    "open_ports",
]


def _export_csv(path: Path, entries: list[dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = dict(e)
            for k in ("a_records", "aaaa_records", "cname_records", "sources",
                       "cookies", "interesting_tags", "high_value_techs"):
                if isinstance(row.get(k), list):
                    row[k] = ";".join(str(v) for v in row[k])
            if isinstance(row.get("open_ports"), dict):
                row["open_ports"] = ";".join(f"{p}/{s}" for p, s in row["open_ports"].items())
            if isinstance(row.get("technologies"), list):
                row["technologies"] = ";".join(t.get("name", "") for t in row["technologies"])
            writer.writerow(row)
