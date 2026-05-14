"""Extract API endpoints, subdomain references and hardcoded secrets from JS assets.

Extraction pipeline
-------------------
1. jsbeautifier  (optional dep) — reformats minified/obfuscated JS into
   readable code before regex runs.  On minified files this alone recovers
   50-80 % more endpoints that would otherwise be invisible on a single line.

2. LinkFinder regex — the battle-tested pattern from d3mondev/linkfinder used
   by thousands of bug bounty hunters.  Catches URLs and paths that semantic
   patterns miss.

3. Semantic patterns — purpose-built regex for fetch/axios/XHR, variable
   assignments, env vars, template literals, /api/* string prefixes, router
   declarations, webpack chunk maps, and Next.js manifests.

HTML parsing:
  · <script src="...">  and  <link rel="preload" href="...as=script">
  · Inline <script> blocks
  · Next.js __NEXT_DATA__ JSON island (route map)
  · Next.js __BUILD_MANIFEST (all registered pages)
  · Webpack / Vite chunk discovery inside bundles

Secret detection (20+ families):
  AWS, Google, GitHub (PAT + fine-grained), Stripe, Slack (token + webhook),
  Discord, Twilio, SendGrid, Mailchimp, Mailgun, Firebase, Square, Shopify,
  JWT, private keys, Bearer tokens, generic api_key / secret / password
  — entropy filtering + placeholder rejection to minimise noise.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Optional jsbeautifier — import once, degrade gracefully if not installed
# ---------------------------------------------------------------------------
try:
    import jsbeautifier as _jsb
    _BEAUTIFIER_OPTS = _jsb.default_options()
    _BEAUTIFIER_OPTS.unescape_strings = True
    _BEAUTIFIER_OPTS.eval_code = False
    _BEAUTIFIER_OPTS.wrap_line_length = 0
    _HAS_BEAUTIFIER = True
except ImportError:
    _HAS_BEAUTIFIER = False

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

_MAX_JS_BYTES = 3 * 1024 * 1024       # skip JS files > 3 MB
_BEAUTIFY_MAX_BYTES = 1 * 1024 * 1024  # beautify only files ≤ 1 MB (perf guard)
_MINIFIED_LINE_THRESHOLD = 2_000       # avg chars/line above this → minified
_MAX_JS_PER_HOST = 20                  # cap JS files fetched per live host
_MAX_CHUNK_DISCOVERY = 8               # extra chunk URLs to follow per bundle
_JS_TIMEOUT = 15.0
_MIN_SECRET_LEN = 8
_MIN_ENTROPY = 3.3                     # Shannon bits/char for generic patterns

# ---------------------------------------------------------------------------
# LinkFinder regex  (d3mondev/linkfinder — battle-tested in bug bounty)
# Catches URLs and relative paths between quote delimiters in any JS content.
# Applied after beautification so it works on de-minified code too.
# ---------------------------------------------------------------------------
_LINKFINDER_RE = re.compile(
    r"""(?:"|')"""
    r"""("""
    r"""(?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}"""
    r"""|(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,}"""
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"']{0,}|)"""
    r"""|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"']{0,}|)"""
    r"""|[a-zA-Z0-9_\-/]{3,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"']{0,}|)"""
    r""")"""
    r"""(?:"|')""",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    kind: str      # e.g. "aws_access_key_id", "jwt", "generic_secret"
    value: str     # raw matched value
    context: str   # ≤120-char excerpt around the match
    js_url: str


@dataclass
class JSFileFinding:
    js_url: str
    endpoints: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)


@dataclass
class JSHostResult:
    host_url: str
    js_files_fetched: int = 0
    findings: list[JSFileFinding] = field(default_factory=list)

    @property
    def all_endpoints(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for f in self.findings:
            for ep in f.endpoints:
                if ep not in seen:
                    seen.add(ep)
                    out.append(ep)
        return out

    @property
    def all_subdomains(self) -> set[str]:
        out: set[str] = set()
        for f in self.findings:
            out.update(f.subdomains)
        return out

    @property
    def all_secrets(self) -> list[SecretFinding]:
        out: list[SecretFinding] = []
        for f in self.findings:
            out.extend(f.secrets)
        return out


# ---------------------------------------------------------------------------
# HTML / asset discovery patterns
# ---------------------------------------------------------------------------

_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+\bsrc\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)
_PRELOAD_JS_RE = re.compile(
    r'<link[^>]+rel=["\'](?:preload|modulepreload)["\'][^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)
_INLINE_SCRIPT_RE = re.compile(
    r'<script(?![^>]+\bsrc\s*=)[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_NEXTJS_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(\{.*?\})</script>',
    re.IGNORECASE | re.DOTALL,
)
_NEXT_BUILD_MANIFEST_RE = re.compile(
    r'self\.__BUILD_MANIFEST\s*[=,]\s*(\{[^;]{30,60000}\})',
    re.DOTALL,
)
# Webpack chunk map inside bundles: "chunkId":"path/chunk.hash.js"
_WEBPACK_CHUNK_PATH_RE = re.compile(
    r'["\`]((?:[/_a-zA-Z0-9.-]+/)?(?:chunk|static|assets|dist|js)'
    r'/[a-zA-Z0-9_/.-]*[a-f0-9]{6,}\.[a-zA-Z0-9]{2,5})["\`]',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Endpoint extraction patterns
# (name, compiled_pattern) — group(1) is the URL/path
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # fetch("url") / axios.get("url") / $http.get("url") / this._http.post("url")
    ("fetch_axios",
     re.compile(
         r'(?:fetch|axios\s*\.\s*\w+|this\s*\.\s*\w*[Hh]ttp\s*\.\s*\w+'
         r'|this\s*\.\s*(?:service|api|http)\s*\.\s*\w+'
         r'|\$(?:http|resource)\s*(?:\.\s*\w+)?'
         r'|\$\.(?:ajax|get|post|put|delete|patch))\s*\(\s*["`\']([^`"\'<>{}\s]{4,200})["`\']',
         re.IGNORECASE,
     )),

    # XMLHttpRequest.open("GET", "url")
    ("xhr_open",
     re.compile(
         r'\.open\s*\(\s*["`\'][A-Z]+["`\']\s*,\s*["`\']([^`"\'<>{}\s]{4,200})["`\']',
         re.IGNORECASE,
     )),

    # url / endpoint / baseUrl / apiUrl = "value"
    ("url_assignment",
     re.compile(
         r'(?:^|[,{\s;(\[])\s*'
         r'(?:url|endpoint|path|routes?|href|action|baseUrl?|apiUrl?'
         r'|API_URL|BASE_URL|BASE_PATH|API_BASE|API_ROOT|API_HOST'
         r'|API_ENDPOINT|API_PREFIX|SERVER_URL|BACKEND_URL|SERVICE_URL'
         r'|backendUrl|serviceUrl|remoteUrl|requestUrl|targetUrl)\s*'
         r'[=:]\s*["`\']([^`"\'<>{}\s]{4,200})["`\']',
         re.IGNORECASE | re.MULTILINE,
     )),

    # Bundler env vars baked in at build time
    ("env_var",
     re.compile(
         r'(?:REACT_APP|VUE_APP|NUXT_APP|NEXT_PUBLIC|GATSBY|VITE)_'
         r'(?:API_URL|API_HOST|API_BASE|ENDPOINT|BASE_URL|HOST|BACKEND'
         r'|SERVER|SERVICE_URL|GRAPHQL|WS_URL)\s*[=:]\s*["`\']([^`"\'<>{}\s]{4,200})["`\']',
         re.IGNORECASE,
     )),

    # Template literals: `${configVar}/api/v2/users`
    ("template_path",
     re.compile(r'`\$\{[^}]{1,60}\}(/[a-zA-Z0-9_/{}:?=&%@#.-]{2,120})`')),

    # Strings starting with a recognised API prefix
    ("api_path",
     re.compile(
         r'["`\']'
         r'(/(?:'
         r'api|v\d+[a-z]?|rest|gql|graphql|trpc|rpc|grpc'
         r'|ws|wss|socket\.io|sockjs|webhooks?|callbacks?'
         r'|auth|oauth2?|sso|saml|login|logout|signin|signout|signup|register'
         r'|token|refresh|revoke|authorize|session|csrf'
         r'|user[s]?|account[s]?|profile[s]?|me|self|whoami|identity'
         r'|admin|dashboard|manage|management|panel|console|bo|backoffice'
         r'|search|query|suggest|autocomplete|typeahead|lookup'
         r'|data|record[s]?|item[s]?|resource[s]?|entity|entities|object[s]?'
         r'|upload|download|export|import|file[s]?|media|attachment[s]?|asset[s]?|blob[s]?'
         r'|health|healthz|ping|ready|alive|status|metrics|stats|telemetry|monitor'
         r'|config|settings|preference[s]?|feature[s]?|flag[s]?|toggle[s]?'
         r'|notification[s]?|message[s]?|event[s]?|activity|audit|log[s]?|feed'
         r'|payment[s]?|order[s]?|invoice[s]?|billing|subscription[s]?|checkout|cart'
         r'|product[s]?|catalog|inventory|price[s]?|sku[s]?'
         r'|report[s]?|analytics|insight[s]?|chart[s]?|stat[s]?'
         r'|internal|private|debug|_internal|__api|priv'
         r')[/a-zA-Z0-9_{}():?=&%@!#$*+.,;-]{0,150})'
         r'["`\']',
         re.IGNORECASE,
     )),

    # Full HTTP(S) URLs embedded as string literals
    ("absolute_url",
     re.compile(
         r'["`\'](https?://[a-zA-Z0-9._-]{4,120}/[a-zA-Z0-9_/.-]{2,150}'
         r'(?:\?[^`"\'<>\s]{0,100})?)["`\']',
     )),

    # React-Router / Vue-Router / Angular route paths: path: "/users/:id"
    ("router_path",
     re.compile(
         r'\bpath\s*[=:]\s*["`\']([/a-zA-Z0-9:_.-]{3,120})["`\']',
         re.IGNORECASE,
     )),
]

# Extensions that mark an endpoint as a static asset (filter out)
_STATIC_EXT_RE = re.compile(
    r'\.(css|less|sass|scss|png|jpe?g|gif|svg|ico|webp|bmp|tiff?'
    r'|mp[34]|avi|mov|mkv|webm|flv|wmv|wav|ogg|opus'
    r'|woff2?|ttf|eot|otf'
    r'|pdf|docx?|xlsx?|pptx?|zip|tar|gz|rar|7z|exe|dmg|apk|deb|rpm'
    r'|map|chunk\.js\.map)(\?[^"\'`]*)?$',
    re.IGNORECASE,
)
_STATIC_PREFIX_RE = re.compile(
    r'^/(?:static|assets|images?|img|icons?|fonts?|media|vendor|node_modules)/',
    re.IGNORECASE,
)
_CDN_NOISE_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com'
    r'|ajax\.googleapis\.com|fonts\.gstatic\.com|fonts\.googleapis\.com'
    r'|maxcdn\.bootstrapcdn\.com|stackpath\.bootstrapcdn\.com)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Secret detection patterns
# (kind, pattern, high_confidence)
#   high_confidence=True  → skip entropy check (pattern is specific enough)
#   high_confidence=False → require _entropy(value) >= _MIN_ENTROPY
# ---------------------------------------------------------------------------

_SECRET_DEFS: list[tuple[str, re.Pattern, bool]] = [
    # ---- Cloud provider keys ------------------------------------------------
    ("aws_access_key_id",
     re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
     True),

    ("aws_secret_access_key",
     re.compile(
         r'(?:aws_secret_access_key|secret_access_key|aws[_\-]secret)["\'\s]*[=:]+\s*["\']?([A-Za-z0-9/+=]{40})\b',
         re.IGNORECASE,
     ), True),

    ("google_api_key",
     re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
     True),

    ("google_oauth_client_id",
     re.compile(r'\b([0-9]{12,20}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b'),
     True),

    # ---- Source control tokens -----------------------------------------------
    ("github_token_classic",
     re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b'),
     True),

    ("github_fine_grained_pat",
     re.compile(r'\b(github_pat_[A-Za-z0-9_]{82})\b'),
     True),

    # ---- Payment ---------------------------------------------------------------
    ("stripe_secret_key",
     re.compile(r'\b(sk_(?:live|test)_[A-Za-z0-9]{24,99})\b'),
     True),

    ("stripe_publishable_key",
     re.compile(r'\b(pk_(?:live|test)_[A-Za-z0-9]{24,99})\b'),
     True),

    # ---- Messaging / notification -------------------------------------------
    ("slack_bot_token",
     re.compile(r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,30})\b'),
     True),

    ("slack_webhook_url",
     re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24,30})'),
     True),

    ("discord_webhook_url",
     re.compile(r'(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{68})'),
     True),

    ("twilio_account_sid",
     re.compile(r'\b(AC[a-fA-F0-9]{32})\b'),
     True),

    ("twilio_auth_token",
     re.compile(
         r'(?:auth_token|authToken)\s*[=:\'",\s]+([a-fA-F0-9]{32})\b',
         re.IGNORECASE,
     ), True),

    ("sendgrid_api_key",
     re.compile(r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b'),
     True),

    ("mailchimp_api_key",
     re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b'),
     True),

    ("mailgun_api_key",
     re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'),
     True),

    # ---- Auth tokens / JWT -------------------------------------------------
    ("jwt",
     re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
     True),

    ("bearer_token",
     re.compile(
         r'[Bb]earer\s+([A-Za-z0-9_\-./+=]{20,200})\b',
     ), False),

    # ---- Infrastructure -------------------------------------------------------
    ("private_key_header",
     re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?:\s+BLOCK)?-----)'),
     True),

    ("square_access_token",
     re.compile(r'\b(sq0atp-[0-9A-Za-z\-_]{22,43})\b'),
     True),

    ("shopify_token",
     re.compile(r'\b(shp(?:at|pa|ca)_[a-fA-F0-9]{32})\b'),
     True),

    # ---- Firebase / Google services ----------------------------------------
    ("firebase_api_key",
     re.compile(
         r'(?:apiKey|firebase[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,80})["\']',
         re.IGNORECASE,
     ), False),

    # ---- Generic high-signal patterns (need entropy check) -----------------
    ("generic_secret",
     re.compile(
         r'(?:^|[\s,{;(\[])'
         r'(?:password|passwd|pwd|secret|token'
         r'|api[_-]?key|apikey|api[_-]?(?:secret|token)'
         r'|app[_-]?(?:key|secret|token)'
         r'|auth[_-]?(?:key|token|secret)'
         r'|access[_-]?(?:key|secret|token)'
         r'|client[_-]?secret|encryption[_-]?key'
         r'|signing[_-]?(?:key|secret)|signing[_-]?key'
         r'|consumer[_-]?(?:key|secret)'
         r'|service[_-]?(?:key|account[_-]?key)'
         r'|private[_-]?(?:key|token))\s*[=:]\s*'
         r'["\']([A-Za-z0-9_\-./+=@!#$%^&*]{8,120})["\']',
         re.IGNORECASE | re.MULTILINE,
     ), False),
]

# Strings to skip: placeholders / examples / test values
_PLACEHOLDER_RE = re.compile(
    r'(?i)(?:your[_-]|replace[_-]?|change[_-]?me|insert[_-]'
    r'|<[A-Z_]+>|\{[A-Z_]+\}|example[_-]?|placeholder'
    r'|xxx{3,}|000{3,}|aaa{3,}|test[_-]?(?:key|secret|token|value)?$'
    r'|fake[_-]?|dummy[_-]?|lorem|sample)',
)

_OBVIOUSLY_FAKE = frozenset({
    "null", "undefined", "true", "false", "none", "empty", "n/a",
    "password", "changeme", "admin", "test", "demo", "sample",
    "secret", "replace_me", "todo", "fixme", "unknown",
    "my_secret", "my_token", "my_key", "my_password",
})


# ---------------------------------------------------------------------------
# JS beautification helper
# ---------------------------------------------------------------------------

def _is_minified(content: str) -> bool:
    """Heuristic: if the longest single line exceeds the threshold, it's minified.

    Real-world webpack/rollup/vite bundles produce single lines of 50k–500k
    chars; readable code rarely exceeds 500 chars per line.
    """
    return any(len(line) > _MINIFIED_LINE_THRESHOLD for line in content.splitlines())


def _beautify(content: str) -> str:
    """Reformat minified JS using jsbeautifier when available.

    Falls back to original content if the library is missing, the file is
    too large, or beautification raises an exception.
    """
    if not _HAS_BEAUTIFIER:
        return content
    if len(content.encode("utf-8", errors="replace")) > _BEAUTIFY_MAX_BYTES:
        return content
    if not _is_minified(content):
        return content
    try:
        return _jsb.beautify(content, _BEAUTIFIER_OPTS)
    except Exception:
        return content


# ---------------------------------------------------------------------------
# Helper: entropy
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask(value: str) -> str:
    """Show first 6 + last 4 chars, mask the rest."""
    if len(value) <= 10:
        return "***"
    return value[:6] + "***" + value[-4:]


def _is_secret_valid(value: str, high_confidence: bool) -> bool:
    if not value or len(value) < _MIN_SECRET_LEN:
        return False
    # Placeholder / example check only applies to generic / low-confidence patterns.
    # High-confidence patterns (e.g. AKIA…, eyJ…) are trusted by design even
    # if the matched string happens to contain the word "example".
    if not high_confidence and _PLACEHOLDER_RE.search(value):
        return False
    if value.lower().strip("\"'") in _OBVIOUSLY_FAKE:
        return False
    if not high_confidence and _entropy(value) < _MIN_ENTROPY:
        return False
    return True


# ---------------------------------------------------------------------------
# Endpoint filtering
# ---------------------------------------------------------------------------

def _is_interesting_endpoint(ep: str) -> bool:
    if not ep or len(ep) < 4 or len(ep) > 200:
        return False
    if _STATIC_EXT_RE.search(ep):
        return False
    if ep.startswith("/"):
        if _STATIC_PREFIX_RE.match(ep):
            return False
        if ep.count("/") > 10:
            return False
    if ep.startswith("http"):
        if _CDN_NOISE_RE.search(ep):
            return False
    return True


# ---------------------------------------------------------------------------
# Core extraction functions
# ---------------------------------------------------------------------------

def _extract_endpoints(content: str, base_url: str) -> list[str]:
    """Run LinkFinder + semantic patterns against JS/HTML content."""
    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc
    found: set[str] = set()

    def _add(raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        if raw.startswith("http"):
            parsed_ep = urlparse(raw)
            if parsed_ep.netloc == base_host:
                raw = parsed_ep.path or raw
            elif _CDN_NOISE_RE.search(raw):
                return
        if _is_interesting_endpoint(raw):
            found.add(raw)

    # 1. LinkFinder regex — broad sweep between quote delimiters
    for m in _LINKFINDER_RE.finditer(content):
        _add(m.group(1))

    # 2. Semantic patterns — higher specificity, catch assignments / calls / etc.
    for _name, pattern in _ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            try:
                _add(m.group(1))
            except IndexError:
                pass

    return sorted(found)


def _extract_subdomains(content: str, root_domains: set[str]) -> set[str]:
    """Find any hostname in content that is a subdomain of a root_domain."""
    _URL_RE = re.compile(
        r'https?://([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)',
    )
    found: set[str] = set()
    for m in _URL_RE.finditer(content):
        host = m.group(1).lower()
        for root in root_domains:
            if host.endswith(f".{root}") and host != root:
                found.add(host)
                break
    return found


def _extract_secrets(content: str, js_url: str) -> list[SecretFinding]:
    """Detect hardcoded credentials and API keys."""
    findings: list[SecretFinding] = []
    # Deduplicate by raw value: the first (most specific) pattern to match wins.
    # Prevents a Google API key being reported as google_api_key +
    # firebase_api_key + generic_secret simultaneously.
    seen_values: set[str] = set()

    for kind, pattern, high_confidence in _SECRET_DEFS:
        for m in pattern.finditer(content):
            try:
                value = m.group(1)
            except IndexError:
                value = m.group(0)
            if not value:
                continue
            if not _is_secret_valid(value, high_confidence):
                continue
            if value in seen_values:
                continue
            seen_values.add(value)

            # Build context excerpt
            start = max(0, m.start() - 50)
            end = min(len(content), m.end() + 50)
            ctx = content[start:end].replace("\n", " ").replace("\r", "").strip()
            if len(ctx) > 120:
                ctx = ctx[:120] + "…"

            findings.append(SecretFinding(kind=kind, value=value, context=ctx, js_url=js_url))

    return findings


# ---------------------------------------------------------------------------
# JS file discovery
# ---------------------------------------------------------------------------

def _find_js_urls_in_html(html: str, base_url: str) -> list[str]:
    """Extract all JS file URLs from HTML (script src + preload links)."""
    urls: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        raw = m.group(1).strip()
        if raw and not raw.startswith("data:"):
            urls.append(urljoin(base_url, raw))
    for m in _PRELOAD_JS_RE.finditer(html):
        raw = m.group(1).strip()
        if raw and not raw.startswith("data:"):
            urls.append(urljoin(base_url, raw))
    return list(dict.fromkeys(urls))  # preserve order, deduplicate


def _find_chunk_urls_in_js(js_content: str, base_url: str) -> list[str]:
    """Discover lazily-loaded webpack/vite chunk URLs inside a bundle."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = []
    for m in _WEBPACK_CHUNK_PATH_RE.finditer(js_content):
        path = m.group(1)
        full = path if path.startswith("http") else urljoin(origin, "/" + path.lstrip("/"))
        if urlparse(full).netloc == parsed.netloc:
            urls.append(full)
    return list(dict.fromkeys(urls))[:_MAX_CHUNK_DISCOVERY]


# ---------------------------------------------------------------------------
# Next.js / framework-specific extractors
# ---------------------------------------------------------------------------

def _extract_next_data_paths(html: str) -> list[str]:
    """Pull URL paths from Next.js __NEXT_DATA__ JSON island."""
    paths: list[str] = []
    m = _NEXTJS_DATA_RE.search(html)
    if not m:
        return paths
    try:
        data = json.loads(m.group(1))
        _collect_url_strings(data, paths, depth=0)
    except Exception:
        pass
    return paths


def _extract_build_manifest_routes(content: str) -> list[str]:
    """Pull all registered pages from Next.js __BUILD_MANIFEST."""
    paths: list[str] = []
    m = _NEXT_BUILD_MANIFEST_RE.search(content)
    if not m:
        return paths
    try:
        data = json.loads(m.group(1))
        for page in data.get("sortedPages", []):
            if isinstance(page, str) and page.startswith("/"):
                paths.append(page)
        # Also collect any string values that look like paths
        _collect_url_strings(data, paths, depth=0)
    except Exception:
        pass
    return paths


def _collect_url_strings(obj: object, out: list[str], depth: int) -> None:
    """Recursively collect strings that look like URL paths from JSON objects."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_url_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_url_strings(item, out, depth + 1)
    elif isinstance(obj, str) and obj.startswith("/") and 3 < len(obj) < 200:
        if not _STATIC_EXT_RE.search(obj):
            out.append(obj)


# ---------------------------------------------------------------------------
# Per-file content analysis
# ---------------------------------------------------------------------------

def _analyze_content(content: str, url: str, root_domains: set[str]) -> JSFileFinding:
    """Beautify (if needed) then run all extractors on a single content string."""
    f = JSFileFinding(js_url=url)

    # Reformat minified code so regex patterns work on readable lines
    readable = _beautify(content)

    f.endpoints = _extract_endpoints(readable, url)
    # Add Next.js build manifest routes (use original content — manifest is JSON)
    extra_routes = _extract_build_manifest_routes(content)
    for r in extra_routes:
        if _is_interesting_endpoint(r) and r not in f.endpoints:
            f.endpoints.append(r)
    f.subdomains = sorted(_extract_subdomains(readable, root_domains))
    # Run secrets on both the beautified and original text.
    # jsbeautifier can break escape sequences, so the original catches tokens
    # that the readable version misses, and vice-versa.
    from_readable = _extract_secrets(readable, url)
    seen_vals = {s.value for s in from_readable}
    for s in _extract_secrets(content, url):
        if s.value not in seen_vals:
            from_readable.append(s)
            seen_vals.add(s.value)
    f.secrets = from_readable
    return f


# ---------------------------------------------------------------------------
# HTTP fetch helper
# ---------------------------------------------------------------------------

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str | None:
    """Fetch text content; return None on error, wrong type, or size > limit."""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=_JS_TIMEOUT)
        if resp.status_code != 200:
            return None
        ct = resp.headers.get("content-type", "")
        if ct and not any(t in ct for t in ("javascript", "html", "text", "json", "ecmascript")):
            return None
        cl = resp.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > _MAX_JS_BYTES:
            return None
        content = resp.text
        if len(content.encode("utf-8", errors="replace")) > _MAX_JS_BYTES:
            return None
        return content
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-host processing
# ---------------------------------------------------------------------------

async def _process_host(
    host_url: str,
    sem: asyncio.Semaphore,
    root_domains: set[str],
) -> JSHostResult:
    result = JSHostResult(host_url=host_url)

    async with httpx.AsyncClient(
        headers={"User-Agent": _UA},
        follow_redirects=True,
        timeout=_JS_TIMEOUT,
    ) as client:
        # 1. Fetch base HTML
        async with sem:
            html = await _fetch_text(client, host_url)
        if not html:
            return result

        # 2. Inline <script> blocks
        inline = " ".join(m.group(1) for m in _INLINE_SCRIPT_RE.finditer(html))
        if inline.strip():
            f = _analyze_content(inline, host_url + "#inline", root_domains)
            if f.endpoints or f.secrets or f.subdomains:
                result.findings.append(f)

        # 3. __NEXT_DATA__ paths
        next_paths = _extract_next_data_paths(html)
        if next_paths:
            nf = JSFileFinding(js_url=host_url + "#__NEXT_DATA__")
            nf.endpoints = [p for p in dict.fromkeys(next_paths) if _is_interesting_endpoint(p)]
            if nf.endpoints:
                result.findings.append(nf)

        # 4. Collect JS file URLs and process them
        js_queue: list[str] = _find_js_urls_in_html(html, host_url)
        fetched: set[str] = set()
        i = 0

        while js_queue and i < _MAX_JS_PER_HOST:
            url = js_queue.pop(0)
            if url in fetched:
                continue
            fetched.add(url)

            async with sem:
                js_text = await _fetch_text(client, url)
            if not js_text:
                continue

            result.js_files_fetched += 1
            i += 1

            f = _analyze_content(js_text, url, root_domains)
            if f.endpoints or f.secrets or f.subdomains:
                result.findings.append(f)

            # Discover webpack/vite chunks inside this bundle
            if i < _MAX_JS_PER_HOST - _MAX_CHUNK_DISCOVERY:
                for chunk_url in _find_chunk_urls_in_js(js_text, url):
                    if chunk_url not in fetched and chunk_url not in js_queue:
                        js_queue.append(chunk_url)

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_js_extraction(
    probe_results: list,       # list[ProbeResult]
    root_domains: set[str],
    cfg: "Settings",
) -> list[JSHostResult]:
    """Extract JS endpoints, subdomains and secrets from all live hosts."""

    # Build unique live URL list (prefer HTTPS)
    live_urls: list[str] = []
    seen: set[str] = set()
    for pr in probe_results:
        if pr.live_urls:
            url = pr.live_urls[0]
            if url not in seen:
                seen.add(url)
                live_urls.append(url)

    if not live_urls:
        return []

    console.print(f"[dim]JS extraction: {len(live_urls)} live hosts[/]")

    # Cap concurrency at 10 (polite and avoids hammering WAFs)
    sem = asyncio.Semaphore(min(cfg.concurrency, 10))
    host_results: list[JSHostResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]JS extraction"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("extracting", total=len(live_urls))
        for coro in asyncio.as_completed(
            [_process_host(url, sem, root_domains) for url in live_urls]
        ):
            hr = await coro
            if hr.findings:
                host_results.append(hr)
            progress.advance(task)

    total_ep = sum(len(r.all_endpoints) for r in host_results)
    total_sec = sum(len(r.all_secrets) for r in host_results)
    total_sub = sum(len(r.all_subdomains) for r in host_results)

    sec_style = "bold red" if total_sec else "dim"
    console.print(
        f"[bold]JS:[/] {total_ep} endpoints, "
        f"{total_sub} subdomain refs, "
        f"[{sec_style}]{total_sec} potential secrets[/]"
    )
    return host_results


def write_js_output(host_results: list[JSHostResult], out_dir) -> None:  # out_dir: Path
    """Write js_findings.json, js_endpoints.txt, js_secrets.txt, js_subdomains.txt."""
    from pathlib import Path as _Path

    out_dir = _Path(out_dir)
    if not host_results:
        return

    all_endpoints: set[str] = set()
    all_secrets: list[SecretFinding] = []
    all_subdomains: set[str] = set()
    findings_data: dict = {}

    for hr in host_results:
        all_endpoints.update(hr.all_endpoints)
        all_secrets.extend(hr.all_secrets)
        all_subdomains.update(hr.all_subdomains)

        if not hr.findings:
            continue
        findings_data[hr.host_url] = {
            "js_files_fetched": hr.js_files_fetched,
            "files": [
                {
                    "url": f.js_url,
                    "endpoints": f.endpoints,
                    "subdomains": f.subdomains,
                    "secrets": [
                        {"kind": s.kind, "value": s.value, "context": s.context}
                        for s in f.secrets
                    ],
                }
                for f in hr.findings
            ],
        }

    # js_findings.json — full detail, including raw secret values
    (out_dir / "js_findings.json").write_text(
        json.dumps(findings_data, indent=2, ensure_ascii=False) + "\n"
    )

    # js_endpoints.txt — sorted unique paths/URLs
    if all_endpoints:
        (out_dir / "js_endpoints.txt").write_text(
            "\n".join(sorted(all_endpoints)) + "\n"
        )

    # js_secrets.txt — masked values for safe logging / sharing
    if all_secrets:
        lines: list[str] = [
            f"# {len(all_secrets)} potential secret(s) found",
            "# Raw values are in js_findings.json",
            "",
        ]
        for s in all_secrets:
            lines += [
                f"[{s.kind}]",
                f"  Value   : {_mask(s.value)}",
                f"  Source  : {s.js_url}",
                f"  Context : {s.context}",
                "",
            ]
        (out_dir / "js_secrets.txt").write_text("\n".join(lines))
        console.print(
            f"[bold red]  {len(all_secrets)} potential secret(s) → js_secrets.txt[/]"
        )

    # js_subdomains.txt — additional subdomains discovered in JS
    if all_subdomains:
        (out_dir / "js_subdomains.txt").write_text(
            "\n".join(sorted(all_subdomains)) + "\n"
        )
