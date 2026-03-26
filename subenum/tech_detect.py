"""Technology fingerprinting from HTTP probe responses.

Identifies web technologies by matching against known patterns in
response headers, cookies, body content and meta tags. Each match
produces a tech name and optional version string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from rich.console import Console

console = Console(stderr=True)


@dataclass
class TechMatch:
    name: str
    version: str = ""
    category: str = ""  # e.g. "cms", "server", "framework", "cdn", "waf"
    confidence: str = "high"


# ---------------------------------------------------------------------------
# Fingerprint rules. Each rule matches against a specific signal.
# ---------------------------------------------------------------------------

# Header-based detections: (header_name_lower, pattern, tech_name, category)
_HEADER_RULES: list[tuple[str, re.Pattern, str, str]] = [
    ("server", re.compile(r"nginx(?:/([\d.]+))?", re.I), "Nginx", "server"),
    ("server", re.compile(r"apache(?:/([\d.]+))?", re.I), "Apache", "server"),
    ("server", re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.I), "IIS", "server"),
    ("server", re.compile(r"LiteSpeed", re.I), "LiteSpeed", "server"),
    ("server", re.compile(r"openresty(?:/([\d.]+))?", re.I), "OpenResty", "server"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", "cdn"),
    ("server", re.compile(r"AmazonS3", re.I), "AWS S3", "cloud"),
    ("server", re.compile(r"gunicorn(?:/([\d.]+))?", re.I), "Gunicorn", "server"),
    ("server", re.compile(r"uvicorn", re.I), "Uvicorn", "server"),
    ("x-powered-by", re.compile(r"PHP(?:/([\d.]+))?", re.I), "PHP", "language"),
    ("x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET", "framework"),
    ("x-powered-by", re.compile(r"Express", re.I), "Express.js", "framework"),
    ("x-powered-by", re.compile(r"Next\.js(?:\s*([\d.]+))?", re.I), "Next.js", "framework"),
    ("x-powered-by", re.compile(r"Phusion Passenger", re.I), "Passenger", "server"),
    ("x-generator", re.compile(r"WordPress(?:\s*([\d.]+))?", re.I), "WordPress", "cms"),
    ("x-generator", re.compile(r"Drupal(?:\s*([\d.]+))?", re.I), "Drupal", "cms"),
    ("x-drupal-cache", re.compile(r".", re.I), "Drupal", "cms"),
    ("x-aspnet-version", re.compile(r"([\d.]+)", re.I), "ASP.NET", "framework"),
    ("x-amz-cf-id", re.compile(r".", re.I), "AWS CloudFront", "cdn"),
    ("x-amz-request-id", re.compile(r".", re.I), "AWS S3", "cloud"),
    ("x-vercel-id", re.compile(r".", re.I), "Vercel", "hosting"),
    ("x-netlify-request-id", re.compile(r".", re.I), "Netlify", "hosting"),
    ("x-github-request-id", re.compile(r".", re.I), "GitHub", "hosting"),
    ("cf-ray", re.compile(r".", re.I), "Cloudflare", "cdn"),
    ("x-cache", re.compile(r"Varnish", re.I), "Varnish", "cache"),
    ("x-cache", re.compile(r"HIT.*CloudFront|CloudFront", re.I), "AWS CloudFront", "cdn"),
    ("via", re.compile(r"Varnish", re.I), "Varnish", "cache"),
    ("via", re.compile(r"cloudfront", re.I), "AWS CloudFront", "cdn"),
    ("x-firebase-hosting", re.compile(r".", re.I), "Firebase", "hosting"),
    ("set-cookie", re.compile(r"JSESSIONID", re.I), "Java Servlet", "framework"),
    ("set-cookie", re.compile(r"ASP\.NET_SessionId", re.I), "ASP.NET", "framework"),
    ("set-cookie", re.compile(r"PHPSESSID", re.I), "PHP", "language"),
    ("set-cookie", re.compile(r"laravel_session", re.I), "Laravel", "framework"),
    ("set-cookie", re.compile(r"wp-settings|wordpress", re.I), "WordPress", "cms"),
    ("set-cookie", re.compile(r"__cfduid|__cf_bm", re.I), "Cloudflare", "cdn"),
    # --- WAF / Security ---
    ("server", re.compile(r"Sucuri", re.I), "Sucuri WAF", "waf"),
    ("server", re.compile(r"AkamaiGHost", re.I), "Akamai WAF", "waf"),
    ("server", re.compile(r"StackPath", re.I), "StackPath WAF", "waf"),
    ("server", re.compile(r"DDoS-Guard", re.I), "DDoS-Guard", "waf"),
    ("server", re.compile(r"Barracuda", re.I), "Barracuda WAF", "waf"),
    ("server", re.compile(r"FortiWeb", re.I), "FortiWeb WAF", "waf"),
    ("server", re.compile(r"BIG-IP|BIGIP", re.I), "F5 BIG-IP", "waf"),
    ("x-sucuri-id", re.compile(r".", re.I), "Sucuri WAF", "waf"),
    ("x-sucuri-cache", re.compile(r".", re.I), "Sucuri WAF", "waf"),
    ("x-iinfo", re.compile(r".", re.I), "Imperva WAF", "waf"),
    ("x-cdn", re.compile(r"Imperva|Incapsula", re.I), "Imperva WAF", "waf"),
    ("x-akamai-transformed", re.compile(r".", re.I), "Akamai WAF", "waf"),
    ("akamai-origin-hop", re.compile(r".", re.I), "Akamai WAF", "waf"),
    ("x-fastly-request-id", re.compile(r".", re.I), "Fastly", "cdn"),
    ("x-amzn-waf-action", re.compile(r".", re.I), "AWS WAF", "waf"),
    ("x-amzn-requestid", re.compile(r".", re.I), "AWS ALB", "cloud"),
    ("set-cookie", re.compile(r"incap_ses_|visid_incap_", re.I), "Imperva WAF", "waf"),
    ("set-cookie", re.compile(r"BIGipServer", re.I), "F5 BIG-IP", "waf"),
    ("set-cookie", re.compile(r"barra_counter_session", re.I), "Barracuda WAF", "waf"),
    ("set-cookie", re.compile(r"_citrix_ns_id", re.I), "Citrix ADC", "waf"),
]

# Body-based detections: (pattern, tech_name, category)
_BODY_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', re.I), "WordPress", "cms"),
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', re.I), "Joomla", "cms"),
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', re.I), "Drupal", "cms"),
    (re.compile(r'/wp-content/', re.I), "WordPress", "cms"),
    (re.compile(r'/wp-includes/', re.I), "WordPress", "cms"),
    (re.compile(r'/wp-json/', re.I), "WordPress", "cms"),
    (re.compile(r'wp-emoji-release', re.I), "WordPress", "cms"),
    (re.compile(r'Jira.*?(?:v|version)?\s*([\d.]+)', re.I), "Jira", "issue-tracker"),
    (re.compile(r'atlassian\.net|jira\.', re.I), "Atlassian", "saas"),
    (re.compile(r'confluence', re.I), "Confluence", "wiki"),
    (re.compile(r'Jenkins\s+ver\.\s*([\d.]+)', re.I), "Jenkins", "ci"),
    (re.compile(r'Dashboard \[Jenkins\]', re.I), "Jenkins", "ci"),
    (re.compile(r'GitLab', re.I), "GitLab", "devops"),
    (re.compile(r'Grafana(?:\s+v?([\d.]+))?', re.I), "Grafana", "monitoring"),
    (re.compile(r'Kibana(?:\s+v?([\d.]+))?', re.I), "Kibana", "monitoring"),
    (re.compile(r'Swagger UI', re.I), "Swagger UI", "api-docs"),
    (re.compile(r'redoc\.standalone', re.I), "ReDoc", "api-docs"),
    (re.compile(r'GraphQL Playground|GraphiQL', re.I), "GraphQL", "api"),
    (re.compile(r'<title>phpMyAdmin', re.I), "phpMyAdmin", "database"),
    (re.compile(r'Adminer(?:\s+([\d.]+))?', re.I), "Adminer", "database"),
    (re.compile(r'pgAdmin', re.I), "pgAdmin", "database"),
    (re.compile(r'<title>Elastic', re.I), "Elasticsearch", "database"),
    (re.compile(r'Spring Boot', re.I), "Spring Boot", "framework"),
    (re.compile(r'<title>Apache Tomcat', re.I), "Apache Tomcat", "server"),
    (re.compile(r'React\.createElement|react-root|__next', re.I), "React", "frontend"),
    (re.compile(r'ng-version=["\'](\d[\d.]*)', re.I), "Angular", "frontend"),
    (re.compile(r'Vue\.js|vue-router|vuex', re.I), "Vue.js", "frontend"),
    (re.compile(r'<title>Webmin', re.I), "Webmin", "admin-panel"),
    (re.compile(r'cPanel', re.I), "cPanel", "admin-panel"),
    (re.compile(r'Plesk', re.I), "Plesk", "admin-panel"),
    (re.compile(r'<title>.*MinIO', re.I), "MinIO", "storage"),
    (re.compile(r'<title>Portainer', re.I), "Portainer", "container"),
    (re.compile(r'Traefik', re.I), "Traefik", "proxy"),
    (re.compile(r'Harbor', re.I), "Harbor", "container-registry"),
    (re.compile(r'SonarQube', re.I), "SonarQube", "code-quality"),
    (re.compile(r'Sentry', re.I), "Sentry", "monitoring"),
    (re.compile(r'Prometheus', re.I), "Prometheus", "monitoring"),
    (re.compile(r'RabbitMQ Management', re.I), "RabbitMQ", "message-queue"),
    (re.compile(r'Solr Admin', re.I), "Apache Solr", "search"),
]


def detect_technologies(
    headers: dict[str, str],
    body: str,
    cookies: str = "",
) -> list[TechMatch]:
    """Analyze HTTP response data and return detected technologies."""
    seen: set[str] = set()
    techs: list[TechMatch] = []

    def _add(name: str, version: str, category: str) -> None:
        key = f"{name}|{version}"
        if key not in seen:
            seen.add(key)
            techs.append(TechMatch(name=name, version=version, category=category))

    # Header rules
    for hdr_name, pattern, tech_name, category in _HEADER_RULES:
        hdr_val = headers.get(hdr_name, "")
        if not hdr_val:
            continue
        m = pattern.search(hdr_val)
        if m:
            version = m.group(1) if m.lastindex and m.group(1) else ""
            _add(tech_name, version, category)

    # Cookie-in-header check (set-cookie rules already handled above)
    # Body rules (only scan first 32KB for performance)
    snippet = body[:32768]
    for pattern, tech_name, category in _BODY_RULES:
        m = pattern.search(snippet)
        if m:
            version = m.group(1) if m.lastindex and m.group(1) else ""
            _add(tech_name, version, category)

    return techs


def techs_to_dict(techs: list[TechMatch]) -> list[dict]:
    return [{"name": t.name, "version": t.version, "category": t.category} for t in techs]


# ---------------------------------------------------------------------------
# High-value targets: technologies known to have frequent vulnerabilities
# ---------------------------------------------------------------------------

HIGH_VALUE_TECHS = {
    "Jenkins", "Jira", "Confluence", "GitLab", "phpMyAdmin", "Adminer",
    "pgAdmin", "Elasticsearch", "Kibana", "Grafana", "Webmin", "cPanel",
    "Apache Solr", "RabbitMQ", "MinIO", "Portainer", "SonarQube",
    "Apache Tomcat", "WordPress", "Drupal", "Joomla", "Swagger UI",
    "GraphQL", "Spring Boot", "Harbor", "Prometheus", "Sentry",
}


def flag_high_value(techs: list[TechMatch]) -> list[str]:
    """Return names of detected technologies that are frequently vulnerable."""
    return [t.name for t in techs if t.name in HIGH_VALUE_TECHS]


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------

WAF_TECHS = {
    "Cloudflare", "Sucuri WAF", "Akamai WAF", "Imperva WAF", "AWS WAF",
    "F5 BIG-IP", "Barracuda WAF", "FortiWeb WAF", "DDoS-Guard",
    "StackPath WAF", "Citrix ADC",
}


def flag_waf(techs: list[TechMatch]) -> list[str]:
    """Return names of detected WAF/CDN-with-WAF technologies."""
    return sorted({t.name for t in techs if t.name in WAF_TECHS})
