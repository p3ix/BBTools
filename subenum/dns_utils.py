"""DNS resolution utilities with wildcard detection."""

from __future__ import annotations

import asyncio
import random
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.resolver
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)


@dataclass
class ResolveResult:
    subdomain: str
    resolved: bool = False
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

def _random_label(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


async def detect_wildcard(
    domain: str, resolvers: list[str], timeout: int = 5
) -> set[str]:
    """Probe a random subdomain to detect wildcard DNS.

    Returns the set of A-record IPs if wildcard is detected, empty set otherwise.
    """
    probe = f"_subenum-wdtest-{_random_label()}.{domain}"
    resolver = _make_resolver(resolvers, timeout)
    try:
        answer = await resolver.resolve(probe, "A")
        ips = {rr.to_text() for rr in answer}
        if ips:
            console.print(
                f"[bold yellow]Wildcard DNS detected for {domain} "
                f"(probe resolved to {', '.join(ips)})[/]"
            )
        return ips
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Single resolution
# ---------------------------------------------------------------------------

def _make_resolver(
    resolvers: list[str], timeout: int
) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.nameservers = resolvers
    r.lifetime = timeout
    return r


async def resolve_subdomain(
    sub: str,
    resolvers: list[str],
    timeout: int = 5,
    retries: int = 2,
) -> ResolveResult:
    result = ResolveResult(subdomain=sub)
    resolver = _make_resolver(resolvers, timeout)

    for attempt in range(1, retries + 1):
        try:
            # A records
            try:
                ans_a = await resolver.resolve(sub, "A")
                result.a_records = sorted({rr.to_text() for rr in ans_a})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                pass

            # AAAA records
            try:
                ans_aaaa = await resolver.resolve(sub, "AAAA")
                result.aaaa_records = sorted({rr.to_text() for rr in ans_aaaa})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                pass

            # CNAME records
            try:
                ans_cname = await resolver.resolve(sub, "CNAME")
                result.cname_records = sorted({rr.to_text() for rr in ans_cname})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                pass

            result.resolved = bool(
                result.a_records or result.aaaa_records or result.cname_records
            )
            return result

        except dns.resolver.LifetimeTimeout:
            if attempt == retries:
                return result
            await asyncio.sleep(0.5)
        except Exception:
            return result

    return result


# ---------------------------------------------------------------------------
# Batch resolution
# ---------------------------------------------------------------------------

async def resolve_batch(
    subdomains: list[str],
    cfg: "Settings",
    wildcard_ips: dict[str, set[str]] | None = None,
) -> list[ResolveResult]:
    """Resolve a list of subdomains concurrently with a semaphore."""

    sem = asyncio.Semaphore(cfg.concurrency)
    results: list[ResolveResult] = []
    wcard = wildcard_ips or {}

    async def _resolve_one(sub: str) -> ResolveResult:
        async with sem:
            return await resolve_subdomain(
                sub, cfg.dns_resolvers, cfg.dns_timeout, cfg.dns_retries
            )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]DNS resolution"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("resolving", total=len(subdomains))
        tasks = [_resolve_one(s) for s in subdomains]

        for coro in asyncio.as_completed(tasks):
            res = await coro
            # Filter out wildcard-only results
            root = _root_of(res.subdomain, wcard)
            if root and wcard.get(root):
                wildcard_set = wcard[root]
                real_a = [ip for ip in res.a_records if ip not in wildcard_set]
                if not real_a and not res.aaaa_records and not res.cname_records:
                    res.resolved = False
                    res.a_records = []

            results.append(res)
            progress.advance(task)

    return results


def _root_of(subdomain: str, wcard: dict[str, set[str]]) -> str | None:
    """Find which root domain this subdomain belongs to."""
    for root in wcard:
        if subdomain == root or subdomain.endswith(f".{root}"):
            return root
    return None
