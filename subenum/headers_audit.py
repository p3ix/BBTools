"""Security headers audit for live HTTP hosts.

Analyzes HTTP response headers already collected during probing and flags
missing or misconfigured security headers. Produces findings per host with
severity ratings useful for Bug Bounty reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from subenum.http_probe import ProbeResult

console = Console(stderr=True)


@dataclass
class HeaderFinding:
    subdomain: str
    url: str
    header: str          # header name (or "cors", "cookie:<name>")
    severity: str        # critical / high / medium / low / info
    title: str
    detail: str          # what was found (or "missing")
    recommendation: str


# ---------------------------------------------------------------------------
# Header checks
# ---------------------------------------------------------------------------

def _check_missing_headers(
    subdomain: str, url: str, headers: dict[str, str], is_https: bool
) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []

    rules = [
        {
            "header": "strict-transport-security",
            "title": "Missing HSTS",
            "severity": "high",
            "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "https_only": True,
        },
        {
            "header": "content-security-policy",
            "title": "Missing Content-Security-Policy",
            "severity": "medium",
            "recommendation": "Define a restrictive CSP to prevent XSS and data injection attacks.",
            "https_only": False,
        },
        {
            "header": "x-frame-options",
            "title": "Missing X-Frame-Options (clickjacking)",
            "severity": "medium",
            "recommendation": "X-Frame-Options: DENY  (or use CSP frame-ancestors instead)",
            "https_only": False,
        },
        {
            "header": "x-content-type-options",
            "title": "Missing X-Content-Type-Options",
            "severity": "low",
            "recommendation": "X-Content-Type-Options: nosniff",
            "https_only": False,
        },
        {
            "header": "referrer-policy",
            "title": "Missing Referrer-Policy",
            "severity": "low",
            "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
            "https_only": False,
        },
        {
            "header": "permissions-policy",
            "title": "Missing Permissions-Policy",
            "severity": "info",
            "recommendation": "Add Permissions-Policy to restrict browser feature access.",
            "https_only": False,
        },
    ]

    for rule in rules:
        if rule["https_only"] and not is_https:
            continue
        if rule["header"] not in headers:
            findings.append(HeaderFinding(
                subdomain=subdomain,
                url=url,
                header=rule["header"],
                severity=rule["severity"],
                title=rule["title"],
                detail="missing",
                recommendation=rule["recommendation"],
            ))

    return findings


def _check_cors(
    subdomain: str, url: str, headers: dict[str, str]
) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="access-control-allow-origin",
            severity="medium",
            title="CORS: wildcard origin",
            detail="Access-Control-Allow-Origin: *",
            recommendation="Restrict CORS to specific trusted origins instead of wildcard.",
        ))

    if acao == "null":
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="access-control-allow-origin",
            severity="high",
            title="CORS: null origin allowed",
            detail="Access-Control-Allow-Origin: null",
            recommendation="Never allow the null origin — it can be triggered by sandboxed iframes.",
        ))

    if acao not in ("", "*") and acac == "true":
        # Reflected/arbitrary origin + credentials = critical (but we can only detect
        # static misconfigs from a passive probe — flag for manual verification)
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="access-control-allow-credentials",
            severity="high",
            title="CORS: credentials allowed — verify origin reflection",
            detail=f"ACAO: {acao} + ACAC: true",
            recommendation=(
                "Verify that the origin is not reflected from the request. "
                "If so, this allows cross-origin credential theft."
            ),
        ))

    return findings


def _check_hsts_config(
    subdomain: str, url: str, headers: dict[str, str]
) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        return findings

    parts = [p.strip().lower() for p in hsts.split(";")]
    max_age = 0
    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass

    if max_age < 31536000:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="strict-transport-security",
            severity="low",
            title="HSTS max-age too short",
            detail=f"max-age={max_age} (< 1 year)",
            recommendation="Set max-age to at least 31536000 (1 year).",
        ))

    if "includesubdomains" not in parts:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="strict-transport-security",
            severity="info",
            title="HSTS missing includeSubDomains",
            detail=hsts[:120],
            recommendation="Add includeSubDomains to extend HSTS to all subdomains.",
        ))

    return findings


def _check_csp_weaknesses(
    subdomain: str, url: str, headers: dict[str, str]
) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    csp = headers.get("content-security-policy", "")
    if not csp:
        return findings

    csp_lower = csp.lower()
    if "'unsafe-inline'" in csp_lower:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="content-security-policy",
            severity="medium",
            title="CSP: unsafe-inline allows inline script execution",
            detail=csp[:200],
            recommendation="Remove 'unsafe-inline' and use nonces or hashes instead.",
        ))
    if "'unsafe-eval'" in csp_lower:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="content-security-policy",
            severity="medium",
            title="CSP: unsafe-eval allows dynamic code execution",
            detail=csp[:200],
            recommendation="Remove 'unsafe-eval' to prevent eval-based XSS.",
        ))

    return findings


def _check_cookies(
    subdomain: str, url: str, headers: dict[str, str], is_https: bool
) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    raw_cookies: list[str] = []
    # headers dict has merged headers; for set-cookie we need all values
    # In ProbeResult, response_headers stores the last value per key.
    # We do a best-effort check on the merged set-cookie string.
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return findings

    # Split on comma is unreliable; we check the whole string for common session names
    session_patterns = ["sessionid", "session", "phpsessid", "jsessionid", "auth", "token", "jwt"]
    cookie_lower = set_cookie.lower()

    is_session_cookie = any(p in cookie_lower for p in session_patterns)
    if not is_session_cookie:
        return findings

    if is_https and "secure" not in cookie_lower:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="set-cookie",
            severity="medium",
            title="Session cookie missing Secure flag",
            detail=set_cookie[:120],
            recommendation="Add the Secure flag so the cookie is only sent over HTTPS.",
        ))

    if "httponly" not in cookie_lower:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="set-cookie",
            severity="medium",
            title="Session cookie missing HttpOnly flag",
            detail=set_cookie[:120],
            recommendation="Add HttpOnly to prevent JavaScript access to the session cookie.",
        ))

    if "samesite" not in cookie_lower:
        findings.append(HeaderFinding(
            subdomain=subdomain,
            url=url,
            header="set-cookie",
            severity="low",
            title="Session cookie missing SameSite attribute",
            detail=set_cookie[:120],
            recommendation="Add SameSite=Strict or SameSite=Lax to mitigate CSRF.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main audit entry point
# ---------------------------------------------------------------------------

def audit_headers(probe_results: list["ProbeResult"]) -> list[HeaderFinding]:
    """Run all header checks against probe results and return all findings."""
    all_findings: list[HeaderFinding] = []

    for pr in probe_results:
        if not pr.live_urls:
            continue
        url = pr.live_urls[0]
        is_https = url.startswith("https://")
        hdrs = pr.response_headers

        all_findings.extend(_check_missing_headers(pr.subdomain, url, hdrs, is_https))
        all_findings.extend(_check_cors(pr.subdomain, url, hdrs))
        all_findings.extend(_check_hsts_config(pr.subdomain, url, hdrs))
        all_findings.extend(_check_csp_weaknesses(pr.subdomain, url, hdrs))
        all_findings.extend(_check_cookies(pr.subdomain, url, hdrs, is_https))

    return all_findings


# ---------------------------------------------------------------------------
# Summary + export
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}


def print_headers_summary(findings: list[HeaderFinding]) -> None:
    if not findings:
        return
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = [
        f"[{_SEV_COLOR[sev]}]{sev}:{n}[/]"
        for sev, n in sorted(counts.items(), key=lambda x: _SEV_ORDER.get(x[0], 9))
    ]
    console.print(f"[bold]Security headers:[/] {len(findings)} findings — {', '.join(parts)}")

    # Show high+ findings inline
    high_plus = [f for f in findings if _SEV_ORDER.get(f.severity, 9) <= 1]
    for f in high_plus[:5]:
        color = _SEV_COLOR[f.severity]
        console.print(f"  [{color}]{f.severity.upper()}[/] {f.subdomain} — {f.title}")
    if len(high_plus) > 5:
        console.print(f"  [dim]... and {len(high_plus) - 5} more high/critical findings[/]")


def export_headers_audit(findings: list[HeaderFinding], out_dir: Path) -> None:
    if not findings:
        return

    findings_sorted = sorted(findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.subdomain))

    # JSON
    records = [
        {
            "subdomain": f.subdomain,
            "url": f.url,
            "header": f.header,
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "recommendation": f.recommendation,
        }
        for f in findings_sorted
    ]
    (out_dir / "security_headers.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n"
    )

    # Human-readable report
    lines = ["# Security Headers Audit", ""]
    by_sev: dict[str, list[HeaderFinding]] = {}
    for f in findings_sorted:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in ["critical", "high", "medium", "low", "info"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"## {sev.upper()} ({len(group)})")
        lines.append("")
        for f in group:
            lines.append(f"  [{f.subdomain}] {f.title}")
            lines.append(f"    detail: {f.detail}")
            lines.append(f"    fix:    {f.recommendation}")
            lines.append("")

    (out_dir / "security_headers.txt").write_text("\n".join(lines))
    console.print(f"[dim]Security headers audit → {out_dir}/security_headers.json[/]")
