"""Async port scanning for resolved subdomains.

Scans common high-value ports beyond 80/443 to find hidden services
like admin panels, databases, APIs and debug endpoints.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

if TYPE_CHECKING:
    from subenum.config import Settings

console = Console(stderr=True)

# Ports that commonly expose interesting services in BB targets
HIGH_VALUE_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    25:    "SMTP",
    53:    "DNS",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    2082:  "cPanel",
    2083:  "cPanel SSL",
    2086:  "WHM",
    2087:  "WHM SSL",
    3000:  "Grafana/Node",
    3306:  "MySQL",
    3389:  "RDP",
    4443:  "Alt HTTPS",
    5000:  "Flask/Docker",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    6443:  "Kubernetes API",
    8000:  "Alt HTTP",
    8008:  "Alt HTTP",
    8080:  "Alt HTTP",
    8443:  "Alt HTTPS",
    8888:  "Jupyter/Alt HTTP",
    9000:  "SonarQube/Portainer",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    9443:  "Alt HTTPS",
    10000: "Webmin",
    10250: "Kubelet",
    11211: "Memcached",
    15672: "RabbitMQ Mgmt",
    27017: "MongoDB",
}


@dataclass
class PortResult:
    host: str
    open_ports: dict[int, str] = field(default_factory=dict)  # port -> service hint


async def _check_port(
    host: str, port: int, timeout: float = 3.0
) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def scan_host(
    host: str,
    ports: dict[int, str] | None = None,
    timeout: float = 3.0,
) -> PortResult:
    """Scan a single host on all high-value ports."""
    target_ports = ports or HIGH_VALUE_PORTS
    result = PortResult(host=host)
    port_sem = asyncio.Semaphore(10)

    async def _guarded(port: int) -> tuple[int, bool]:
        async with port_sem:
            return port, await _check_port(host, port, timeout)

    tasks = [asyncio.create_task(_guarded(p)) for p in target_ports]
    for coro in asyncio.as_completed(tasks):
        port, is_open = await coro
        if is_open:
            result.open_ports[port] = target_ports[port]

    return result


async def scan_batch(
    hosts: list[str],
    cfg: "Settings",
    ports: dict[int, str] | None = None,
) -> list[PortResult]:
    """Scan multiple hosts concurrently with a semaphore."""
    sem = asyncio.Semaphore(min(cfg.concurrency, 15))

    async def _scan_one(host: str) -> PortResult:
        async with sem:
            return await scan_host(host, ports)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]Port scanning"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scanning", total=len(hosts))
        tasks = [_scan_one(h) for h in hosts]
        results: list[PortResult] = []
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            progress.advance(task)

    # Only report hosts with interesting ports (exclude 443 since we know it)
    interesting = [r for r in results if any(p not in (80, 443) for p in r.open_ports)]
    if interesting:
        console.print(f"[bold yellow]{len(interesting)}[/] hosts with extra open ports")
        for r in interesting[:10]:
            extras = {p: s for p, s in r.open_ports.items() if p not in (80, 443)}
            port_str = ", ".join(f"{p}/{s}" for p, s in sorted(extras.items()))
            console.print(f"  [yellow]{r.host}[/] -> {port_str}")
        if len(interesting) > 10:
            console.print(f"  [dim]... and {len(interesting) - 10} more[/]")

    return results
