from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Source-level settings
# ---------------------------------------------------------------------------

@dataclass
class SourceCfg:
    enabled: bool = True
    timeout: int = 30
    rate_limit: int = 0  # requests-per-second; 0 = unlimited
    path: str = ""       # only relevant for external binaries


# ---------------------------------------------------------------------------
# Top-level settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    concurrency: int = 20

    # DNS
    dns_timeout: int = 5
    dns_retries: int = 2
    dns_resolvers: list[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"])

    # Per-source configuration
    sources: dict[str, SourceCfg] = field(default_factory=dict)

    # API keys (loaded from env)
    virustotal_key: str = ""
    urlscan_key: str = ""

    def source(self, name: str) -> SourceCfg:
        return self.sources.get(name, SourceCfg())


# ---------------------------------------------------------------------------
# Default source configs
# ---------------------------------------------------------------------------

_DEFAULT_SOURCES: dict[str, dict] = {
    "crtsh":          {"enabled": True, "timeout": 30},
    "virustotal":     {"enabled": True, "timeout": 15, "rate_limit": 4},
    "urlscan":        {"enabled": True, "timeout": 15, "rate_limit": 2},
    "subfinder":      {"enabled": True, "timeout": 120, "path": "subfinder"},
    "amass":          {"enabled": True, "timeout": 300, "path": "amass"},
    "alienvault":     {"enabled": True, "timeout": 20},
    "hackertarget":   {"enabled": True, "timeout": 15},
    "wayback":        {"enabled": True, "timeout": 30},
    "rapiddns":       {"enabled": True, "timeout": 20},
    "anubis":         {"enabled": True, "timeout": 15},
}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _parse_source(name: str, raw: dict | None) -> SourceCfg:
    defaults = _DEFAULT_SOURCES.get(name, {})
    merged = {**defaults, **(raw or {})}
    return SourceCfg(
        enabled=merged.get("enabled", True),
        timeout=merged.get("timeout", 30),
        rate_limit=merged.get("rate_limit", 0),
        path=merged.get("path", ""),
    )


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Build a Settings object from YAML file + environment variables."""

    load_dotenv()  # reads .env if present

    raw: dict = {}
    if config_path and Path(config_path).is_file():
        with open(config_path) as fh:
            raw = yaml.safe_load(fh) or {}

    dns_block = raw.get("dns", {})

    sources_raw: dict = raw.get("sources", {})
    all_source_names = set(_DEFAULT_SOURCES) | set(sources_raw)
    sources = {name: _parse_source(name, sources_raw.get(name)) for name in all_source_names}

    return Settings(
        concurrency=raw.get("concurrency", 20),
        dns_timeout=dns_block.get("timeout", 5),
        dns_retries=dns_block.get("retries", 2),
        dns_resolvers=dns_block.get("resolvers", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]),
        sources=sources,
        virustotal_key=os.getenv("VT_API_KEY", ""),
        urlscan_key=os.getenv("URLSCAN_API_KEY", ""),
    )
