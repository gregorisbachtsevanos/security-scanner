import asyncio
from typing import Iterable, List, Tuple

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 123, 143, 161, 389,
    443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375,
    27017, 3306, 3389, 5432, 5601, 5900, 6379, 8000, 8080, 8443, 9000
]

async def _probe(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False

async def scan_ports(host: str, ports: Iterable[int], concurrency: int = 200) -> List[int]:
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def worker(p):
        async with sem:
            port, ok = await _probe(host, p)
            if ok:
                open_ports.append(port)

    tasks = [asyncio.create_task(worker(p)) for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)
    return sorted(open_ports)
