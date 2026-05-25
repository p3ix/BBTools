"""Interesting subdomain tagger with priority scoring.

Flags subdomains that match known patterns associated with high-value
targets in Bug Bounty (admin panels, staging environments, APIs,
internal tools, databases, CI/CD, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from subenum.http_probe import ProbeResult


@dataclass
class InterestingHit:
    subdomain: str
    score: int         # 1-10, higher = more interesting
    tags: list[str]
    reason: str


# (pattern, score, tag, reason)
_RULES: list[tuple[re.Pattern, int, str, str]] = [
    # Admin / management panels (very high value)
    (re.compile(r"(^|[.-])admin([.-]|$)", re.I), 9, "admin", "Admin panel"),
    (re.compile(r"(^|[.-])panel([.-]|$)", re.I), 8, "admin", "Control panel"),
    (re.compile(r"(^|[.-])dashboard([.-]|$)", re.I), 8, "admin", "Dashboard"),
    (re.compile(r"(^|[.-])manage[r]?([.-]|$)", re.I), 8, "admin", "Management interface"),
    (re.compile(r"(^|[.-])backoffice([.-]|$)", re.I), 9, "admin", "Back office"),
    (re.compile(r"(^|[.-])console([.-]|$)", re.I), 8, "admin", "Console"),
    (re.compile(r"(^|[.-])portal([.-]|$)", re.I), 6, "admin", "Portal"),

    # Internal / non-public environments
    (re.compile(r"(^|[.-])internal([.-]|$)", re.I), 9, "internal", "Internal system"),
    (re.compile(r"(^|[.-])intranet([.-]|$)", re.I), 9, "internal", "Intranet"),
    (re.compile(r"(^|[.-])corp([.-]|$)", re.I), 8, "internal", "Corporate"),
    (re.compile(r"(^|[.-])private([.-]|$)", re.I), 8, "internal", "Private"),
    (re.compile(r"(^|[.-])vpn([.-]|$)", re.I), 7, "internal", "VPN endpoint"),
    (re.compile(r"(^|[.-])remote([.-]|$)", re.I), 6, "internal", "Remote access"),

    # Development / staging / test (often less hardened)
    (re.compile(r"(^|[.-])staging([.-]|$)", re.I), 8, "dev", "Staging environment"),
    (re.compile(r"(^|[.-])stg([.-]|$)", re.I), 8, "dev", "Staging"),
    (re.compile(r"(^|[.-])dev([.-]|$)", re.I), 7, "dev", "Development"),
    (re.compile(r"(^|[.-])test(ing)?([.-]|$)", re.I), 7, "dev", "Testing"),
    (re.compile(r"(^|[.-])qa([.-]|$)", re.I), 7, "dev", "QA"),
    (re.compile(r"(^|[.-])uat([.-]|$)", re.I), 7, "dev", "UAT"),
    (re.compile(r"(^|[.-])sandbox([.-]|$)", re.I), 7, "dev", "Sandbox"),
    (re.compile(r"(^|[.-])preprod([.-]|$)", re.I), 7, "dev", "Pre-production"),
    (re.compile(r"(^|[.-])demo([.-]|$)", re.I), 6, "dev", "Demo"),
    (re.compile(r"(^|[.-])beta([.-]|$)", re.I), 6, "dev", "Beta"),
    (re.compile(r"(^|[.-])canary([.-]|$)", re.I), 6, "dev", "Canary release"),
    (re.compile(r"(^|[.-])debug([.-]|$)", re.I), 9, "dev", "Debug endpoint"),

    # API / services
    (re.compile(r"(^|[.-])api([.-]|$)", re.I), 7, "api", "API endpoint"),
    (re.compile(r"(^|[.-])graphql([.-]|$)", re.I), 8, "api", "GraphQL"),
    (re.compile(r"(^|[.-])grpc([.-]|$)", re.I), 7, "api", "gRPC endpoint"),
    (re.compile(r"(^|[.-])rest([.-]|$)", re.I), 6, "api", "REST API"),
    (re.compile(r"(^|[.-])gateway([.-]|$)", re.I), 7, "api", "API gateway"),
    (re.compile(r"(^|[.-])ws([.-]|$)", re.I), 6, "api", "WebSocket"),
    (re.compile(r"(^|[.-])webhook([.-]|$)", re.I), 6, "api", "Webhook"),

    # CI/CD and DevOps
    (re.compile(r"(^|[.-])jenkins([.-]|$)", re.I), 9, "cicd", "Jenkins CI"),
    (re.compile(r"(^|[.-])gitlab([.-]|$)", re.I), 8, "cicd", "GitLab"),
    (re.compile(r"(^|[.-])github([.-]|$)", re.I), 6, "cicd", "GitHub"),
    (re.compile(r"(^|[.-])ci([.-]|$)", re.I), 7, "cicd", "CI server"),
    (re.compile(r"(^|[.-])cd([.-]|$)", re.I), 6, "cicd", "CD pipeline"),
    (re.compile(r"(^|[.-])deploy([.-]|$)", re.I), 7, "cicd", "Deployment"),
    (re.compile(r"(^|[.-])build([.-]|$)", re.I), 6, "cicd", "Build server"),
    (re.compile(r"(^|[.-])registry([.-]|$)", re.I), 7, "cicd", "Container registry"),
    (re.compile(r"(^|[.-])docker([.-]|$)", re.I), 7, "cicd", "Docker"),
    (re.compile(r"(^|[.-])k8s([.-]|$)", re.I), 8, "cicd", "Kubernetes"),
    (re.compile(r"(^|[.-])kubernetes([.-]|$)", re.I), 8, "cicd", "Kubernetes"),
    (re.compile(r"(^|[.-])argocd([.-]|$)", re.I), 8, "cicd", "ArgoCD"),
    (re.compile(r"(^|[.-])sonar([.-]|$)", re.I), 7, "cicd", "SonarQube"),

    # Databases
    (re.compile(r"(^|[.-])db([.-]|$)", re.I), 8, "database", "Database"),
    (re.compile(r"(^|[.-])database([.-]|$)", re.I), 8, "database", "Database"),
    (re.compile(r"(^|[.-])mysql([.-]|$)", re.I), 8, "database", "MySQL"),
    (re.compile(r"(^|[.-])postgres([.-]|$)", re.I), 8, "database", "PostgreSQL"),
    (re.compile(r"(^|[.-])mongo([.-]|$)", re.I), 8, "database", "MongoDB"),
    (re.compile(r"(^|[.-])redis([.-]|$)", re.I), 8, "database", "Redis"),
    (re.compile(r"(^|[.-])elastic([.-]|$)", re.I), 8, "database", "Elasticsearch"),
    (re.compile(r"(^|[.-])solr([.-]|$)", re.I), 7, "database", "Apache Solr"),

    # Monitoring / logging
    (re.compile(r"(^|[.-])grafana([.-]|$)", re.I), 8, "monitoring", "Grafana"),
    (re.compile(r"(^|[.-])kibana([.-]|$)", re.I), 8, "monitoring", "Kibana"),
    (re.compile(r"(^|[.-])prometheus([.-]|$)", re.I), 8, "monitoring", "Prometheus"),
    (re.compile(r"(^|[.-])monitor([.-]|$)", re.I), 6, "monitoring", "Monitoring"),
    (re.compile(r"(^|[.-])sentry([.-]|$)", re.I), 7, "monitoring", "Sentry"),
    (re.compile(r"(^|[.-])log[s]?([.-]|$)", re.I), 6, "monitoring", "Logging"),
    (re.compile(r"(^|[.-])metrics([.-]|$)", re.I), 6, "monitoring", "Metrics"),
    (re.compile(r"(^|[.-])status([.-]|$)", re.I), 5, "monitoring", "Status page"),

    # Auth
    (re.compile(r"(^|[.-])sso([.-]|$)", re.I), 7, "auth", "SSO"),
    (re.compile(r"(^|[.-])auth([.-]|$)", re.I), 7, "auth", "Authentication"),
    (re.compile(r"(^|[.-])oauth([.-]|$)", re.I), 7, "auth", "OAuth"),
    (re.compile(r"(^|[.-])login([.-]|$)", re.I), 6, "auth", "Login"),
    (re.compile(r"(^|[.-])iam([.-]|$)", re.I), 7, "auth", "IAM"),
    (re.compile(r"(^|[.-])ldap([.-]|$)", re.I), 8, "auth", "LDAP"),

    # Storage / file services
    (re.compile(r"(^|[.-])s3([.-]|$)", re.I), 7, "storage", "S3 storage"),
    (re.compile(r"(^|[.-])storage([.-]|$)", re.I), 6, "storage", "Storage"),
    (re.compile(r"(^|[.-])backup([.-]|$)", re.I), 8, "storage", "Backup"),
    (re.compile(r"(^|[.-])upload([.-]|$)", re.I), 7, "storage", "Upload service"),
    (re.compile(r"(^|[.-])files?([.-]|$)", re.I), 5, "storage", "File service"),
    (re.compile(r"(^|[.-])ftp([.-]|$)", re.I), 7, "storage", "FTP"),

    # Messaging / queue
    (re.compile(r"(^|[.-])jira([.-]|$)", re.I), 8, "tools", "Jira"),
    (re.compile(r"(^|[.-])confluence([.-]|$)", re.I), 8, "tools", "Confluence"),
    (re.compile(r"(^|[.-])wiki([.-]|$)", re.I), 5, "tools", "Wiki"),
    (re.compile(r"(^|[.-])redmine([.-]|$)", re.I), 7, "tools", "Redmine"),
    (re.compile(r"(^|[.-])phpmyadmin([.-]|$)", re.I), 9, "tools", "phpMyAdmin"),
    (re.compile(r"(^|[.-])webmail([.-]|$)", re.I), 7, "tools", "Webmail"),
]


def tag_interesting(subdomains: list[str]) -> list[InterestingHit]:
    """Score and tag subdomains that match interesting patterns."""
    hits: list[InterestingHit] = []

    for sub in subdomains:
        tags: list[str] = []
        reasons: list[str] = []
        max_score = 0

        for pattern, score, tag, reason in _RULES:
            # Match against the subdomain prefix (before root domain)
            if pattern.search(sub):
                tags.append(tag)
                reasons.append(reason)
                max_score = max(max_score, score)

        if tags:
            hits.append(InterestingHit(
                subdomain=sub,
                score=max_score,
                tags=sorted(set(tags)),
                reason=", ".join(sorted(set(reasons))),
            ))

    hits.sort(key=lambda h: (-h.score, h.subdomain))
    return hits


def enrich_with_probe(
    hits: list[InterestingHit],
    probe_results: list["ProbeResult"],
) -> None:
    """Boost interesting scores using HTTP probe data (in-place).

    Boosts applied (capped at 10):
      +2  high-value technology detected (Jenkins, GitLab, Grafana, etc.)
      +1  live and no WAF protection
    Also appends context to the reason string so interesting.txt reflects why.
    """
    probe_map = {p.subdomain: p for p in probe_results}
    for hit in hits:
        pr = probe_map.get(hit.subdomain)
        if pr is None:
            continue
        boost = 0
        extra: list[str] = []
        if pr.high_value_techs:
            boost += 2
            extra.append(f"tech:{','.join(pr.high_value_techs)}")
        if pr.live_urls and not pr.waf:
            boost += 1
            extra.append("no-WAF")
        if boost:
            hit.score = min(10, hit.score + boost)
            hit.reason = hit.reason + " [" + " ".join(extra) + "]"
    hits.sort(key=lambda h: (-h.score, h.subdomain))
