import socket
import ssl
from contextlib import closing
from typing import Optional

def get_hostname_hostport(target: str, default_port: int = 443):
    """
    Accepts host, host:port, or URL.
    Returns hostname, port, scheme.
    """
    target = target.strip()
    scheme = None
    host = target
    port = None

    if target.startswith("http://"):
        scheme = "http"
        host = target[7:]
        port = 80
    elif target.startswith("https://"):
        scheme = "https"
        host = target[8:]
        port = 443

    if "/" in host:
        host = host.split("/", 1)[0]

    if ":" in host:
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    if port is None:
        port = default_port if scheme == "https" else 80 if scheme == "http" else default_port
    return host, port, scheme or ("https" if port == 443 else "http")

def fetch_tls_info(host: str, port: int = 443) -> Optional[dict]:
    try:
        ctx = ssl.create_default_context()
        with closing(socket.create_connection((host, port), timeout=5)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                return {"tls_version": tls_version, "cipher": cipher[0] if cipher else None, "cert": cert}
    except Exception:
        return None
