"""CNAME subdomain takeover detection.

Checks resolved CNAME records against a fingerprint list of services
known to be vulnerable to subdomain takeover when dangling.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console

console = Console(stderr=True)

# Service fingerprints: if a CNAME ends with the pattern AND the subdomain
# fails to resolve A records (or returns a known error page), it's a candidate.
FINGERPRINTS: list[dict[str, str]] = [
    # Cloud providers
    {"cname": ".s3.amazonaws.com", "service": "AWS S3"},
    {"cname": ".s3-website", "service": "AWS S3 Website"},
    {"cname": ".elasticbeanstalk.com", "service": "AWS Elastic Beanstalk"},
    {"cname": ".cloudfront.net", "service": "AWS CloudFront"},
    {"cname": ".amazonaws.com", "service": "AWS (generic)"},
    {"cname": ".azurewebsites.net", "service": "Azure App Service"},
    {"cname": ".cloudapp.azure.com", "service": "Azure Cloud App"},
    {"cname": ".azurefd.net", "service": "Azure Front Door"},
    {"cname": ".blob.core.windows.net", "service": "Azure Blob Storage"},
    {"cname": ".trafficmanager.net", "service": "Azure Traffic Manager"},
    {"cname": ".azure-api.net", "service": "Azure API Management"},
    # Hosting / PaaS
    {"cname": ".herokuapp.com", "service": "Heroku"},
    {"cname": ".herokudns.com", "service": "Heroku DNS"},
    {"cname": ".github.io", "service": "GitHub Pages"},
    {"cname": ".gitlab.io", "service": "GitLab Pages"},
    {"cname": ".netlify.app", "service": "Netlify"},
    {"cname": ".netlify.com", "service": "Netlify"},
    {"cname": ".vercel.app", "service": "Vercel"},
    {"cname": ".now.sh", "service": "Vercel (legacy)"},
    {"cname": ".surge.sh", "service": "Surge.sh"},
    {"cname": ".firebaseapp.com", "service": "Firebase"},
    {"cname": ".web.app", "service": "Firebase Hosting"},
    {"cname": ".fly.dev", "service": "Fly.io"},
    {"cname": ".render.com", "service": "Render"},
    # E-commerce / CMS
    {"cname": ".shopify.com", "service": "Shopify"},
    {"cname": ".myshopify.com", "service": "Shopify"},
    {"cname": ".ghost.io", "service": "Ghost"},
    {"cname": ".wordpress.com", "service": "WordPress.com"},
    {"cname": ".pantheonsite.io", "service": "Pantheon"},
    {"cname": ".webflow.io", "service": "Webflow"},
    # Other
    {"cname": ".bitbucket.io", "service": "Bitbucket"},
    {"cname": ".zendesk.com", "service": "Zendesk"},
    {"cname": ".freshdesk.com", "service": "Freshdesk"},
    {"cname": ".helpjuice.com", "service": "Helpjuice"},
    {"cname": ".helpscoutdocs.com", "service": "HelpScout"},
    {"cname": ".statuspage.io", "service": "Statuspage"},
    {"cname": ".tumblr.com", "service": "Tumblr"},
    {"cname": ".cargocollective.com", "service": "Cargo"},
    {"cname": ".feedpress.me", "service": "FeedPress"},
    {"cname": ".unbounce.com", "service": "Unbounce"},
    {"cname": ".campaignmonitor.com", "service": "Campaign Monitor"},
    {"cname": ".tictail.com", "service": "Tictail"},
    {"cname": ".smugmug.com", "service": "SmugMug"},
    {"cname": ".strikingly.com", "service": "Strikingly"},
    {"cname": ".launchrock.com", "service": "LaunchRock"},
    {"cname": ".pingdom.com", "service": "Pingdom"},
]


@dataclass
class TakeoverCandidate:
    subdomain: str
    cname: str
    service: str


def check_takeover(
    entries: list[dict],
) -> list[TakeoverCandidate]:
    """Scan entries for potential CNAME takeover candidates.

    A candidate is a subdomain that has a CNAME pointing to a known
    vulnerable service AND does not resolve to any A/AAAA records
    (suggesting the target service no longer claims the CNAME).
    """
    candidates: list[TakeoverCandidate] = []

    for entry in entries:
        cnames = entry.get("cname_records", [])
        a_records = entry.get("a_records", [])
        aaaa_records = entry.get("aaaa_records", [])

        # Only flag if there's a CNAME but no A/AAAA (dangling)
        if not cnames:
            continue

        for cname_val in cnames:
            cname_lower = cname_val.lower().rstrip(".")
            for fp in FINGERPRINTS:
                if cname_lower.endswith(fp["cname"]):
                    # Dangling: CNAME exists but no A/AAAA resolution
                    if not a_records and not aaaa_records:
                        candidates.append(TakeoverCandidate(
                            subdomain=entry["subdomain"],
                            cname=cname_val,
                            service=fp["service"],
                        ))
                    break

    if candidates:
        console.print(
            f"\n[bold red]Found {len(candidates)} potential takeover candidate(s)![/]"
        )
        for c in candidates:
            console.print(
                f"  [red]{c.subdomain}[/] -> {c.cname} ([yellow]{c.service}[/])"
            )

    return candidates
