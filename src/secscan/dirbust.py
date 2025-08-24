import httpx
from typing import List, Dict

DEFAULT_WORDS = ["admin", "login", "backup", "old", "test", ".git", ".env", "phpinfo.php", "server-status"]

def dir_bruteforce(base_url: str, words: List[str] = None, timeout: float = 8.0) -> List[Dict]:
    words = words or DEFAULT_WORDS
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    if not base_url.endswith("/"):
        base_url += "/"

    results = []
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        for w in words:
            url = base_url + w
            try:
                r = client.get(url)
                if r.status_code not in (404, 400):
                    results.append({
                        "path": w,
                        "url": str(r.url),
                        "status": r.status_code,
                        "length": len(r.content),
                        "location": r.headers.get("Location")
                    })
            except Exception:
                pass
    return results
