"""Subdomain permutation / mutation wordlist generator.

Generates candidate subdomains from discovered ones by applying common
prefixes, suffixes, and separators. Only first-level subdomains (single
label before root) are permutated to avoid combinatorial explosion.
"""

from __future__ import annotations

from rich.console import Console

console = Console(stderr=True)

MAX_CANDIDATES = 15_000
MAX_CANDIDATES_WORDLIST = 50_000  # higher cap when external wordlist supplied

# Max words used for pairwise combination (word × label).  A 10 k-word list
# would produce millions of candidates; cap keeps resolution time reasonable.
_MAX_PERM_WORDS = 2_000

WORDS: list[str] = [
    "dev", "staging", "stg", "stage", "qa", "uat", "test", "testing",
    "prod", "production", "pre", "preprod", "beta", "alpha", "canary",
    "internal", "int", "private", "priv", "corp", "admin", "panel",
    "api", "api2", "api3", "v1", "v2", "v3", "graphql", "grpc",
    "old", "new", "legacy", "next", "backup", "bak", "bk",
    "temp", "tmp", "demo", "sandbox", "lab", "dr", "mirror",
    "web", "www2", "app", "portal", "gateway", "gw",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "mail", "smtp", "imap", "pop", "mx", "email",
    "vpn", "remote", "proxy", "cdn", "edge", "cache",
    "ci", "cd", "jenkins", "git", "gitlab", "github", "deploy",
    "monitor", "metrics", "grafana", "kibana", "log", "logs", "sentry",
    "auth", "sso", "login", "oauth", "iam", "ldap",
]

SEPARATORS: list[str] = ["-", "."]


def generate_permutations(
    discovered: set[str],
    root_domain: str,
    extra_words: list[str] | None = None,
) -> set[str]:
    """Generate candidate subdomains by mutating discovered ones.

    Only first-level subdomains (single label before root) are used as
    seeds to prevent combinatorial explosion on deep sub-domains like
    ``stg.ar.example.com``.

    If *extra_words* is supplied (e.g. from ``--wordlist``), those words
    replace the built-in list.  The list is capped at ``_MAX_PERM_WORDS``
    entries and the candidate cap is raised to ``MAX_CANDIDATES_WORDLIST``.
    """
    if extra_words is not None:
        words = extra_words[:_MAX_PERM_WORDS]
        cap = MAX_CANDIDATES_WORDLIST
        if len(extra_words) > _MAX_PERM_WORDS:
            console.print(
                f"[dim]Permutations: wordlist trimmed to {_MAX_PERM_WORDS} words "
                f"(use full list with --bruteforce for flat brute-force)[/]"
            )
    else:
        words = WORDS
        cap = MAX_CANDIDATES

    suffix = f".{root_domain}"
    candidates: set[str] = set()

    first_level_labels: set[str] = set()
    for sub in discovered:
        if not sub.endswith(suffix):
            continue
        prefix = sub[: -len(suffix)]
        if "." not in prefix:
            first_level_labels.add(prefix)

    for label in first_level_labels:
        for word in words:
            if word == label:
                continue
            for sep in SEPARATORS:
                candidates.add(f"{word}{sep}{label}{suffix}")
                candidates.add(f"{label}{sep}{word}{suffix}")
                if len(candidates) >= cap:
                    break
            if len(candidates) >= cap:
                break
        if len(candidates) >= cap:
            break

    candidates -= discovered
    candidates.discard(root_domain)

    console.print(
        f"[dim]Generated {len(candidates)} permutation candidates "
        f"from {len(first_level_labels)} first-level labels "
        f"using {len(words)} words[/]"
    )
    return candidates
