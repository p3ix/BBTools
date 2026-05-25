"""DNS brute-force: resolve word.domain for each word in a wordlist.

Works in conjunction with --wordlist.  Only resolved results are returned;
wildcard-matching records are silently dropped.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from subenum.dns_utils import ResolveResult, resolve_subdomain

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

_CHUNK_SIZE = 500  # process wordlist in chunks to bound memory pressure


def load_wordlist(path: Path) -> list[str]:
    """Read a wordlist file, one word per line.  Blank lines and # comments skipped."""
    words: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        word = line.strip().lower()
        if word and not word.startswith("#"):
            words.append(word)
    return words


async def bruteforce_domain(
    domain: str,
    words: list[str],
    cfg: "Settings",
    wildcard_ips: set[str],
    known: set[str] | None = None,
) -> list[ResolveResult]:
    """Resolve ``word.domain`` for every word in *words*.

    Subdomains already in *known* are skipped to avoid redundant queries.
    Returns only results that successfully resolved and are not wildcard matches.
    """
    known_set = known or set()
    candidates = [f"{w}.{domain}" for w in words if f"{w}.{domain}" not in known_set]

    skipped = len(words) - len(candidates)
    note = f" ({skipped} already known, skipped)" if skipped else ""
    console.print(
        f"[dim]Brute-force: {len(words)} words → {len(candidates)} new candidates{note}[/]"
    )

    if not candidates:
        return []

    sem = asyncio.Semaphore(cfg.concurrency)
    # One shared resolver for the whole brute-force batch.
    # skip_aaaa: AAAA records are rarely relevant in brute-force and each
    # query adds a full round-trip; CNAME is kept for takeover detection.
    from subenum.dns_utils import _make_resolver
    shared_resolver = _make_resolver(cfg.dns_resolvers, cfg.dns_timeout)
    found: list[ResolveResult] = []

    async def _resolve(sub: str) -> ResolveResult | None:
        async with sem:
            r = await resolve_subdomain(
                sub, cfg.dns_resolvers, cfg.dns_timeout, cfg.dns_retries,
                skip_aaaa=True, _resolver=shared_resolver,
            )
        if not r.resolved:
            return None
        # Drop pure wildcard matches
        if wildcard_ips:
            real_a = [ip for ip in r.a_records if ip not in wildcard_ips]
            if not real_a and not r.cname_records:
                return None
        return r

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold magenta]Brute-force DNS"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("resolving", total=len(candidates))
        for i in range(0, len(candidates), _CHUNK_SIZE):
            chunk = candidates[i : i + _CHUNK_SIZE]
            for coro in asyncio.as_completed([_resolve(c) for c in chunk]):
                r = await coro
                if r is not None:
                    found.append(r)
                progress.advance(task)

    return found
