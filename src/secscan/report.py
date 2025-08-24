import json
import csv
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table

console = Console()

def print_http_report(data: Dict[str, Any]):
    table = Table(title=f"HTTP Scan: {data.get('target','')}")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    for k in ("final_url","status_code","http_version","server","x_powered_by"):
        table.add_row(k, str(data.get(k)))
    console.print(table)

    sec = data.get("security_headers", {})
    miss = ", ".join(sec.get("missing", [])) or "None"
    findings = sec.get("findings", [])
    console.print(f"[bold]Missing security headers:[/bold] {miss}")
    if findings:
        for f in findings:
            console.print(f" - [yellow]{f}[/yellow]")

    if "tls" in data:
        tls = data["tls"]
        console.print(f"[bold]TLS:[/bold] {tls.get('tls_version')} | Cipher: {tls.get('cipher')}")

def print_ports_report(host: str, open_ports: List[int]):
    table = Table(title=f"Open Ports: {host}")
    table.add_column("Port", justify="right")
    for p in open_ports:
        table.add_row(str(p))
    console.print(table)

def print_dirbust_report(base: str, hits: List[Dict]):
    table = Table(title=f"Dirbust Hits: {base}")
    table.add_column("Status", justify="right")
    table.add_column("Path")
    table.add_column("URL")
    table.add_column("Length", justify="right")
    table.add_column("Location")
    for h in hits:
        table.add_row(str(h["status"]), h["path"], h["url"], str(h["length"]), str(h.get("location")))
    console.print(table)

def save_json(path: str, data: Any):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def save_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
