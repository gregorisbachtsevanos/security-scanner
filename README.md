# SecScan – Security Scanner Tool

> For authorized use only. Scan systems you own or are permitted to test.

## Install (dev)
pip install -e .

## CLI
secscan ports example.com
secscan http https://example.com --json-out results/http.json
secscan dirbust https://example.com --wordlist wordlists/tiny.txt --csv-out results/dirs.csv
secscan scan example.com --out-json results/full.json

## Notes
- Port scan is asynchronous but still polite (default timeouts).
- HTTP checks are passive: headers, TLS, robots, sitemap.
- Dirbust is non-destructive (GET only, no payloads).

## Dockerfile (optional)
```
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["secscan"]
```

**Run examples:**
```
docker build -t secscan .
docker run --rm secscan http https://example.com
```

## How to Use

**Install in dev mode:**
```\
pip install -e .
```

**Run scans:**
```
# Ports
secscan ports example.com --ports 1-1024

# HTTP
secscan http https://example.com --json-out results/http.json

# Dirbust with wordlist
secscan dirbust https://example.com --wordlist wordlists/tiny.txt --csv-out results/dirs.csv

# Combined
secscan scan example.com --out-json results/full.json
```
