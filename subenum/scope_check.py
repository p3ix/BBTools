"""Third-party / CDN detection via CNAME analysis.

Identifies subdomains that point to well-known third-party services
(CDNs, SaaS, hosting) so hunters can prioritise direct origin servers.
"""

from __future__ import annotations

# (cname_suffix, service_label)
_THIRD_PARTY_CNAMES: list[tuple[str, str]] = [
    # CDN / Edge
    (".cloudfront.net", "AWS CloudFront"),
    (".akamaiedge.net", "Akamai"),
    (".akamai.net", "Akamai"),
    (".edgekey.net", "Akamai"),
    (".edgesuite.net", "Akamai"),
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    (".cloudflare.net", "Cloudflare"),
    (".cdn.cloudflare.net", "Cloudflare"),
    (".azureedge.net", "Azure CDN"),
    (".stackpathdns.com", "StackPath"),
    (".sucuridns.com", "Sucuri"),
    (".incapdns.net", "Imperva"),
    (".impervadns.net", "Imperva"),
    # Cloud hosting
    (".amazonaws.com", "AWS"),
    (".elb.amazonaws.com", "AWS ELB"),
    (".s3.amazonaws.com", "AWS S3"),
    (".azurewebsites.net", "Azure"),
    (".cloudapp.azure.com", "Azure"),
    (".azurefd.net", "Azure Front Door"),
    (".blob.core.windows.net", "Azure Blob"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".googleusercontent.com", "Google Cloud"),
    (".appspot.com", "Google App Engine"),
    (".run.app", "Google Cloud Run"),
    (".firebaseapp.com", "Firebase"),
    (".web.app", "Firebase"),
    # PaaS / Hosting
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".vercel.app", "Vercel"),
    (".vercel-dns.com", "Vercel"),
    (".github.io", "GitHub Pages"),
    (".gitlab.io", "GitLab Pages"),
    (".fly.dev", "Fly.io"),
    (".render.com", "Render"),
    (".surge.sh", "Surge"),
    (".pantheonsite.io", "Pantheon"),
    # SaaS
    (".shopify.com", "Shopify"),
    (".myshopify.com", "Shopify"),
    (".zendesk.com", "Zendesk"),
    (".freshdesk.com", "Freshdesk"),
    (".statuspage.io", "Statuspage"),
    (".webflow.io", "Webflow"),
    (".ghost.io", "Ghost"),
    (".hubspot.net", "HubSpot"),
    (".mailchimp.com", "Mailchimp"),
    (".wpengine.com", "WP Engine"),
    (".wordpress.com", "WordPress.com"),
    (".squarespace.com", "Squarespace"),
    (".unbounce.com", "Unbounce"),
    (".campaignmonitor.com", "Campaign Monitor"),
]


def detect_third_party(cname_records: list[str]) -> str:
    """Return the third-party service name if any CNAME matches, else ''."""
    for cname_val in cname_records:
        cn = cname_val.lower().rstrip(".")
        for suffix, label in _THIRD_PARTY_CNAMES:
            if cn.endswith(suffix):
                return label
    return ""


def enrich_entries(entries: list[dict]) -> None:
    """Add ``third_party`` field to each entry in-place."""
    for entry in entries:
        cnames = entry.get("cname_records", [])
        entry["third_party"] = detect_third_party(cnames)
