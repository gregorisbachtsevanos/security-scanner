import json
import asyncio
import click
from typing import Optional, Tuple, List

from .ports import scan_ports, COMMON_PORTS
from .httpcheck import http_scan
from .dirbust import dir_bruteforce
from .report import (
    print_http_report, print_ports_report, print_dirbust_report,
    save_json, save_csv
)
from .utils import get_hostname_hostport

@click.group(help="Security Scanner (for authorized testing only).")
def main():
    pass

@main.command("ports")
@click.argument("target")
@click.option("--ports", "ports_str", help="Comma or dash list (e.g. 80,443,8080 or 1-1024).")
@click.option("--concurrency", default=200, show_default=True, help="Concurrent scans.")
def ports_cmd(target: str, ports_str: Optional[str], concurrency: int):
    host, _, _ = get_hostname_hostport(target)
    ports = _parse_ports(ports_str) if ports_str else COMMON_PORTS
    open_ports = asyncio.run(scan_ports(host, ports, concurrency=concurrency))
    print_ports_report(host, open_ports)

def _parse_ports(spec: str) -> List[int]:
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return sorted(out)

@main.command("http")
@click.argument("target")
@click.option("--timeout", default=10.0, show_default=True, help="HTTP timeout seconds.")
@click.option("--json-out", "json_out", type=click.Path(), help="Save JSON report to path.")
def http_cmd(target: str, timeout: float, json_out: Optional[str]):
    data = http_scan(target, timeout=timeout)
    print_http_report(data)
    if json_out:
        save_json(json_out, data)
        click.echo(f"Saved JSON: {json_out}")

@main.command("dirbust")
@click.argument("base")
@click.option("--wordlist", type=click.Path(exists=True), help="Path to wordlist file.")
@click.option("--timeout", default=8.0, show_default=True)
@click.option("--csv-out", "csv_out", type=click.Path(), help="Save CSV results.")
def dirbust_cmd(base: str, wordlist: Optional[str], timeout: float, csv_out: Optional[str]):
    words = None
    if wordlist:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    hits = dir_bruteforce(base, words=words, timeout=timeout)
    print_dirbust_report(base, hits)
    if csv_out and hits:
        save_csv(csv_out, hits, ["status","path","url","length","location"])
        click.echo(f"Saved CSV: {csv_out}")

@main.command("scan")
@click.argument("target")
@click.option("--ports", "ports_str", help="Override ports (e.g. 80,443 or 1-1024).")
@click.option("--concurrency", default=200, show_default=True)
@click.option("--timeout", default=10.0, show_default=True, help="HTTP timeout seconds.")
@click.option("--out-json", type=click.Path(), help="Save combined JSON report.")
def scan_cmd(target: str, ports_str: Optional[str], concurrency: int, timeout: float, out_json: Optional[str]):
    """Run combined scan: ports + HTTP + lightweight dirbust of common paths."""
    host, _, scheme = get_hostname_hostport(target)
    ports = _parse_ports(ports_str) if ports_str else COMMON_PORTS

    open_ports = asyncio.run(scan_ports(host, ports, concurrency=concurrency))
    http_result = http_scan(f"{scheme}://{host}", timeout=timeout)
    # very small dirbust (hardcoded tiny list) to avoid heavy load
    hits = dir_bruteforce(f"{scheme}://{host}", words=None, timeout=timeout)

    click.echo("")  # spacing
    print_ports_report(host, open_ports)
    print_http_report(http_result)
    print_dirbust_report(host, hits)

    if out_json:
        save_json(out_json, {
            "target": host,
            "open_ports": open_ports,
            "http": http_result,
            "dirbust": hits
        })
        click.echo(f"Saved JSON: {out_json}")
