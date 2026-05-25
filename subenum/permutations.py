"""Subdomain permutation / mutation wordlist generator.

Generates candidate subdomains from discovered ones by applying common
prefixes, suffixes, and separators. Only first-level subdomains (single
label before root) are permutated to avoid combinatorial explosion.
"""

from __future__ import annotations

import re
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

# Versioned with explicit separator: api-v2, api_v2, api.v2
_VERSION_WITH_SUFFIX_RE = re.compile(r"^(.+?)[-_.]v(\d+)$", re.I)
# Versioned prefix: v2-service, v3_api (separator included in group 2)
_VERSION_WITH_PREFIX_RE = re.compile(r"^v(\d+)([-_.].*)", re.I)
# Trailing short number: dev1, test02, stg3
_TRAILING_NUM_RE = re.compile(r"^(.+?)(\d{1,2})$")


def _number_variants(base: str) -> list[str]:
    """Expand ``base`` with common numeric suffixes: base1, base-1, base01, base2 …"""
    out = []
    for n in (1, 2, 3):
        out.append(f"{base}{n}")
        out.append(f"{base}-{n}")
        out.append(f"{base}0{n}")
    return out


def _version_variants(label: str) -> list[str]:
    """Generate adjacent version labels for versioned patterns.

    - ``api-v2``  → ``api-v1``, ``api-v3``, ``api-v4``, ``api-v5``
    - ``v3-service`` → ``v1-service``, ``v2-service``, ``v4-service``, ``v5-service``
    - ``dev1``    → ``dev``, ``dev2``, ``dev3``, ``dev01``, ``dev02``
    """
    variants: list[str] = []

    # api-v2, api_v2, api.v2 style (separator required before version marker)
    m = _VERSION_WITH_SUFFIX_RE.match(label)
    if m:
        base, version = m.group(1), int(m.group(2))
        sep = label[len(base)]  # the separator char between base and v
        for v in range(1, 7):
            if v != version:
                variants.append(f"{base}{sep}v{v}")
        return variants

    # v2-service, v3api style
    m = _VERSION_WITH_PREFIX_RE.match(label)
    if m:
        version, suffix = int(m.group(1)), m.group(2)
        for v in range(1, 7):
            if v != version:
                variants.append(f"v{v}{suffix}")
        return variants

    # dev1, test02, stg3 style (trailing 1-2 digit number)
    m = _TRAILING_NUM_RE.match(label)
    if m:
        base, num_str = m.group(1), m.group(2)
        num = int(num_str)
        # Plain variants: base, base2, base3
        variants.append(base)
        for n in range(1, 4):
            if n != num:
                variants.append(f"{base}{n}")
        # Zero-padded variants: base01, base02
        for n in range(1, 4):
            padded = f"{base}0{n}"
            if padded != label:
                variants.append(padded)

    return variants


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

    # Collect extra candidates from version/number mutations of discovered labels
    mutation_candidates: set[str] = set()
    for label in first_level_labels:
        for variant in _version_variants(label):
            if variant and variant != label:
                mutation_candidates.add(f"{variant}{suffix}")
        for variant in _number_variants(label):
            mutation_candidates.add(f"{variant}{suffix}")

    # Pairwise word × label combinations
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
        # Also expand the word itself with number suffixes
        for variant in _number_variants(label):
            candidates.add(f"{variant}{suffix}")
        if len(candidates) >= cap:
            break

    candidates |= mutation_candidates
    candidates -= discovered
    candidates.discard(root_domain)

    console.print(
        f"[dim]Generated {len(candidates)} permutation candidates "
        f"from {len(first_level_labels)} first-level labels "
        f"({len(mutation_candidates)} from version/number mutations) "
        f"using {len(words)} words[/]"
    )
    return candidates
