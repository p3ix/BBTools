"""Resume / checkpoint support.

Persists per-domain scan state to a JSON file so that an interrupted run
(dropped VPS connection, timeout, SIGINT) can be resumed without repeating
the expensive source-gathering and DNS-resolution phases.

Checkpoint file layout:
    {
        "version": 1,
        "phases": {
            "example.com": {
                "done": true,
                "entries": [...],          # already-built entry dicts
                "source_counts": {...},    # {src: count}
                "takeover_candidates": [...],
                "interesting_hits": [...]
            }
        },
        "probe_done": false,
        "probe_results": [...]             # populated when probe_done = true
    }
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console(stderr=True)

_VERSION = 1


class CheckpointManager:
    """Read/write scan state for a single run directory."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = {
            "version": _VERSION,
            "phases": {},
            "probe_done": False,
        }
        if path.is_file():
            try:
                loaded = json.loads(path.read_text())
                done_count = sum(
                    1 for v in loaded.get("phases", {}).values() if v.get("done")
                )
                self._data = loaded
                console.print(
                    f"[bold cyan]Checkpoint loaded — "
                    f"{done_count} domain(s) already complete[/]"
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                console.print("[yellow]Checkpoint file unreadable — starting fresh[/]")

    # ------------------------------------------------------------------
    # Domain-level state
    # ------------------------------------------------------------------

    def is_domain_done(self, domain: str) -> bool:
        return self._data["phases"].get(domain, {}).get("done", False)

    def get_domain(self, domain: str) -> dict[str, Any] | None:
        return self._data["phases"].get(domain)

    def save_domain(
        self,
        domain: str,
        entries: list[dict],
        source_counts: dict[str, int],
        takeover_candidates: list,
        interesting_hits: list,
    ) -> None:
        """Persist everything known about *domain* after enumeration finishes."""
        self._data["phases"][domain] = {
            "done": True,
            "entries": entries,
            "source_counts": source_counts,
            "takeover_candidates": [dataclasses.asdict(c) for c in takeover_candidates],
            "interesting_hits": [dataclasses.asdict(h) for h in interesting_hits],
        }
        self._flush()
        console.print(f"[dim]Checkpoint saved for {domain}[/]")

    # ------------------------------------------------------------------
    # Probe phase (global — runs after all domains are enumerated)
    # ------------------------------------------------------------------

    @property
    def probe_done(self) -> bool:
        return self._data.get("probe_done", False)

    def save_probe(self, probe_results: list) -> None:
        self._data["probe_done"] = True
        self._data["probe_results"] = [dataclasses.asdict(p) for p in probe_results]
        self._flush()

    def load_probe(self) -> list[dict] | None:
        return self._data.get("probe_results")

    # ------------------------------------------------------------------

    def _flush(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False))
