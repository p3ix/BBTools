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
    domain: str, resolvers: list[str], timeout: int = 4
) -> set[str]:
    """Probe a random subdomain to detect wildcard DNS."""
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
# Resolver factory
# ---------------------------------------------------------------------------

def _make_resolver(resolvers: list[str], timeout: int) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.nameservers = resolvers
    r.lifetime = timeout
    return r


# ---------------------------------------------------------------------------
# Single resolution — A + CNAME + AAAA run in parallel
# ---------------------------------------------------------------------------

async def resolve_subdomain(
    sub: str,
    resolvers: list[str],
    timeout: int = 4,
    retries: int = 2,
    *,
    skip_aaaa: bool = False,
    _resolver: dns.asyncresolver.Resolver | None = None,
) -> ResolveResult:
    """Resolve A, CNAME (and optionally AAAA) records in parallel.

    Pass ``_resolver`` to reuse a pre-built resolver across many calls
    (avoids creating a new object per subdomain in batch contexts).
    Set ``skip_aaaa=True`` for brute-force/permutation passes where
    AAAA records are rarely useful and the query just adds latency.
    """
    result = ResolveResult(subdomain=sub)
    r = _resolver or _make_resolver(resolvers, timeout)

    async def _query(qtype: str) -> list[str]:
        for attempt in range(retries):
            try:
                ans = await r.resolve(sub, qtype)
                return sorted({rr.to_text() for rr in ans})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers):
                return []
            except dns.resolver.LifetimeTimeout:
                if attempt < retries - 1:
                    await asyncio.sleep(0.1)
            except Exception:
                return []
        return []

    if skip_aaaa:
        a_records, cname_records = await asyncio.gather(_query("A"), _query("CNAME"))
        aaaa_records: list[str] = []
    else:
        a_records, cname_records, aaaa_records = await asyncio.gather(
            _query("A"), _query("CNAME"), _query("AAAA")
        )

    result.a_records = a_records
    result.cname_records = cname_records
    result.aaaa_records = aaaa_records
    result.resolved = bool(a_records or aaaa_records or cname_records)
    return result


# ---------------------------------------------------------------------------
# Batch resolution
# ---------------------------------------------------------------------------

async def resolve_batch(
    subdomains: list[str],
    cfg: "Settings",
    wildcard_ips: dict[str, set[str]] | None = None,
    skip_aaaa: bool = False,
) -> list[ResolveResult]:
    """Resolve a list of subdomains concurrently.

    A single resolver is shared across all coroutines to avoid creating
    thousands of resolver objects for large brute-force/permutation batches.
    ``skip_aaaa=True`` cuts query count per subdomain from 3→2 for batch
    passes where AAAA data isn't needed.
    """
    sem = asyncio.Semaphore(cfg.concurrency)
    results: list[ResolveResult] = []
    wcard = wildcard_ips or {}

    # One shared resolver for the whole batch
    shared_resolver = _make_resolver(cfg.dns_resolvers, cfg.dns_timeout)

    async def _resolve_one(sub: str) -> ResolveResult:
        async with sem:
            return await resolve_subdomain(
                sub, cfg.dns_resolvers, cfg.dns_timeout, cfg.dns_retries,
                skip_aaaa=skip_aaaa, _resolver=shared_resolver,
            )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]DNS resolution"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("resolving", total=len(subdomains))
        coros = [_resolve_one(s) for s in subdomains]

        for coro in asyncio.as_completed(coros):
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
    for root in wcard:
        if subdomain == root or subdomain.endswith(f".{root}"):
            return root
    return None
