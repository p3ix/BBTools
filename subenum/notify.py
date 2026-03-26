"""Webhook notifications for monitoring workflows.

Sends alerts to Discord, Slack or generic webhooks when new subdomains,
takeover candidates, or high-value targets are found. Particularly useful
when using --diff for continuous monitoring.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from rich.console import Console

console = Console(stderr=True)


def _get_webhook_url() -> str:
    return os.getenv("WEBHOOK_URL", "")


def _detect_type(url: str) -> str:
    if "discord.com/api/webhooks" in url:
        return "discord"
    if "hooks.slack.com" in url:
        return "slack"
    return "generic"


def _build_discord_payload(title: str, body: str, color: int = 0x00FF00) -> dict:
    return {
        "embeds": [{
            "title": title,
            "description": body[:4000],
            "color": color,
        }]
    }


def _build_slack_payload(title: str, body: str) -> dict:
    return {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body[:3000]}},
        ]
    }


def _build_generic_payload(title: str, body: str) -> dict:
    return {"title": title, "body": body}


async def send_notification(
    title: str,
    body: str,
    color: int = 0x00FF00,
) -> None:
    """Send a notification to the configured webhook."""
    url = _get_webhook_url()
    if not url:
        return

    hook_type = _detect_type(url)

    if hook_type == "discord":
        payload = _build_discord_payload(title, body, color)
    elif hook_type == "slack":
        payload = _build_slack_payload(title, body)
    else:
        payload = _build_generic_payload(title, body)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code >= 400:
                console.print(f"[yellow]Webhook returned {resp.status_code}[/]")
    except Exception as exc:
        console.print(f"[yellow]Webhook error: {exc}[/]")


async def notify_results(
    total_subs: int,
    resolved: int,
    live: int,
    takeover_count: int,
    new_subs: list[str] | None = None,
    high_value: list[str] | None = None,
    domains: list[str] | None = None,
) -> None:
    """Build and send a summary notification after a scan completes."""
    url = _get_webhook_url()
    if not url:
        return

    target_str = ", ".join(domains or ["unknown"])
    lines = [
        f"**Targets:** {target_str}",
        f"**Subdomains:** {total_subs} total, {resolved} resolved, {live} live",
    ]

    if takeover_count:
        lines.append(f"**Takeover candidates:** {takeover_count}")

    if new_subs:
        sub_list = "\n".join(f"  + {s}" for s in new_subs[:15])
        lines.append(f"**New subdomains ({len(new_subs)}):**\n{sub_list}")
        if len(new_subs) > 15:
            lines.append(f"  ... and {len(new_subs) - 15} more")

    if high_value:
        lines.append(f"**High-value tech:** {', '.join(set(high_value))}")

    body = "\n".join(lines)
    color = 0xFF0000 if takeover_count else (0xFFA500 if new_subs else 0x00FF00)
    title = f"subenum scan: {target_str}"

    await send_notification(title, body, color)
