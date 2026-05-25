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

# Reduced timeout: TCP SYN on a well-connected VPS either answers fast or
# doesn't answer at all — 1.5s is enough without wasting time on dead ports.
_PORT_TIMEOUT = 1.5


@dataclass
class PortResult:
    host: str
    open_ports: dict[int, str] = field(default_factory=dict)


async def _check_port(host: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool]:
    """Return (port, is_open). Semaphore is passed in from the batch layer."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=_PORT_TIMEOUT,
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return port, False


async def scan_host(
    host: str,
    sem: asyncio.Semaphore,
    ports: dict[int, str] | None = None,
) -> PortResult:
    """Scan a single host on all high-value ports using a shared semaphore."""
    target_ports = ports or HIGH_VALUE_PORTS
    result = PortResult(host=host)

    tasks = [asyncio.create_task(_check_port(host, p, sem)) for p in target_ports]
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
    """Scan multiple hosts concurrently.

    Uses a single global semaphore across all hosts and ports so the total
    number of open TCP connections is bounded without double-counting.
    Port count × host concurrency with separate per-host semaphores was
    creating O(hosts × 10) simultaneous connections — unnecessarily high.
    """
    # One semaphore for all connections: hosts × ports_per_host but bounded.
    # 300 parallel TCP attempts is comfortable for a VPS with good networking.
    total_conn_limit = min(cfg.concurrency * 3, 500)
    global_sem = asyncio.Semaphore(total_conn_limit)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]Port scanning"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task_bar = progress.add_task("scanning", total=len(hosts))
        host_tasks = [asyncio.create_task(scan_host(h, global_sem, ports)) for h in hosts]
        results: list[PortResult] = []
        for coro in asyncio.as_completed(host_tasks):
            res = await coro
            results.append(res)
            progress.advance(task_bar)

    # Only report hosts with interesting ports (exclude 80/443)
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
