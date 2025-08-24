import httpx
from typing import Dict, Any
from .utils import get_hostname_hostport, fetch_tls_info

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

def analyze_headers(headers: httpx.Headers) -> Dict[str, Any]:
    h = {k.lower(): v for k, v in headers.items()}
    missing = [name for name in SEC_HEADERS if name not in h]
    findings = []

    if "content-security-policy" not in h:
        findings.append("Missing CSP (Content-Security-Policy).")
    if "strict-transport-security" not in h:
        findings.append("Missing HSTS (Strict-Transport-Security).")
    if h.get("x-frame-options", "").lower() not in ("deny", "sameorigin"):
        findings.append("X-Frame-Options not set to DENY or SAMEORIGIN (clickjacking risk).")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append("X-Content-Type-Options not set to nosniff.")
    if "referrer-policy" not in h:
        findings.append("Missing Referrer-Policy.")
    return {"missing": missing, "findings": findings}

def http_scan(target: str, timeout: float = 10.0) -> Dict[str, Any]:
    host, port, scheme = get_hostname_hostport(target)
    url = f"{scheme}://{host}:{port}"
    result: Dict[str, Any] = {"target": url}

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            r = client.get(url)
            result["final_url"] = str(r.url)
            result["status_code"] = r.status_code
            result["http_version"] = r.http_version
            result["headers"] = dict(r.headers)
            result["security_headers"] = analyze_headers(r.headers)
            result["server"] = r.headers.get("Server")
            result["x_powered_by"] = r.headers.get("X-Powered-By")

            # Try robots and sitemap
            for path in ("/robots.txt", "/sitemap.xml"):
                try:
                    rr = client.get(url + path)
                    result[path.strip("/")] = {"status": rr.status_code, "size": len(rr.content)}
                except Exception:
                    result[path.strip("/")] = {"status": None}
    except Exception as e:
        result["error"] = str(e)

    # TLS info (if HTTPS)
    if scheme == "https":
        tls = fetch_tls_info(host, port)
        if tls:
            result["tls"] = tls
    return result
