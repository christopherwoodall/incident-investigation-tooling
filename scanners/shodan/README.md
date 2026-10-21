# Shodan (`scanners/shodan`)

Collects host banners, alert metadata, facet counts, and DNS records from the Shodan REST API (`https://api.shodan.io`) to identify exposed AI-agent control panels, tool servers, and inference gateways.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (incremental alert & banner discovery), `search` (banner search, count facets, host IP, domain DNS) |
| **Primary Endpoints** | `GET /shodan/alert/info`, `GET /shodan/host/search`, `GET /shodan/host/count`, `GET /shodan/host/{ip}`, `GET /dns/domain/{domain}` |
| **Error Behavior** | Raises `RuntimeError("SHODAN_API_KEY is required")` when key is unset; fails loudly on HTTP errors |
| **Auth Env Var** | `SHODAN_API_KEY` (required; passed as `?key=***`, redacted in output records) |
| **Default User-Agent** | `"Shodan-Python/1.31.0"` (prevents Cloudflare HTTP 403 challenges on API error responses) |
| **Timeout / Delay / Limit** | `90.0s` / `1.0s` / `50` (`scan.window_hours`: `168`) |
| **Output File** | `./data/shodan.jsonl` |
| **Emitted Tags** | `["shodan", "banner"]`, `["shodan", "alert"]`, `["shodan", "count"]`, `["shodan", "host"]`, `["shodan", "dns"]` |
| **Upstream Docs** | [developer.shodan.io/api](https://developer.shodan.io/api) · [shodan.io/search/filters](https://www.shodan.io/search/filters) |

---

## History & Surface Context

Shodan indexes exposed HTTP titles, TLS certificates, and service banners across IPv4/IPv6. In agent infrastructure investigations, operators frequently leave agent harnesses (`MCP Inspector`, `OpenHands`, `OpenDevin`, `Cairn`, `Strix`, `Hermes Agent`) bound to `0.0.0.0`.

Two upstream constraints shape this collector:
1. **Single-filter query strings**: The Shodan REST API returns `HTTP 400 ("The search query was invalid")` when boolean `OR` combines multiple `http.title:` filters. `scanners/config.yaml` therefore splits each title or product filter into its own query entry.
2. **Zero-credit facet counts (`--count`)**: Free-tier Shodan API keys cannot use filter expressions on `/shodan/host/search` (`HTTP 401/403`), whereas `/shodan/host/count` supports filter expressions and facet breakdowns (`org,country,port,asn`) with zero query credits via `shodan search --count`.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
export SHODAN_API_KEY="your-api-key"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners shodan scan --json` | `scanners shodan search --json` |
| **2. Console Alias** | `shodan scan --json` | `shodan search --json` |
| **3. `uv run` Script** | `uv run scanners/shodan/scan.py --json` | `uv run scanners/shodan/search.py --json` |
| **4. Direct Script** | `./scanners/shodan/scan.py --json` | `./scanners/shodan/search.py --json` |

---

## CLI Reference

### `shodan scan` (`scanners/shodan/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <query>` | `list[str]` | `shodan.scan.targets` | Repeatable scan query override (appends `after:<YYYY-MM-DD>` unless `after:` is present). |
| `--hours <float>` | `float` | `168.0` | Lookback window in hours when no prior `./data/shodan.jsonl` timestamp exists. |
| `--limit <int>` | `int` | `50` | Maximum banners or alerts returned per target query. |
| `--user-agent <str>` | `str` | `"Shodan-Python/1.31.0"` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/shodan.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `shodan search` (`scanners/shodan/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <query>` | `list[str]` | `shodan.queries` | Repeatable Shodan search query string. |
| `--ip <ip>` | `str` | `None` | Query `/shodan/host/{ip}` for a specific IPv4/IPv6 host. |
| `--domain <domain>` | `str` | `None` | Query `/dns/domain/{domain}` for subdomains and DNS records. |
| `--count` | `bool` | `False` | Query `/shodan/host/count` directly instead of `/shodan/host/search`. |
| `--facets <csv>` | `str` | `None` | Comma-separated facets (e.g., `org,country,port,asn`). |
| `--page <int>` | `int` | `1` | Result page number for `/shodan/host/search`. |
| `--limit <int>` | `int` | `50` | Maximum banners emitted per query. |
| `--history` | `bool` | `False` | Include historical banners when querying `--ip`. |
| `--minify` | `bool` | `False` | Minify `/shodan/host/{ip}` output payload. |
| `--since-days <float>` | `float` | `None` | Append `after:<YYYY-MM-DD>` calculated from `now - since_days`. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/shodan.jsonl`. |
| `--user-agent <str>` | `str` | `"Shodan-Python/1.31.0"` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/shodan.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
shodan:
  base_url: "https://api.shodan.io"
  api_key: "${oc.env:SHODAN_API_KEY,''}"
  user_agent: "Shodan-Python/1.31.0"
  headers:
    Accept: "application/json"
  timeout: 90.0
  delay: 1.0
  limit: 50
  queries:
    - 'http.title:"Cairn"'
    - 'http.title:"Strix"'
    - 'product:"Hermes Agent"'
    - 'http.title:"OpenHands"'
    - 'http.title:"OpenDevin"'
    - 'http.title:"MCP Inspector"'
    - "ip:45.14.13.147"
  scan:
    window_hours: 168
    targets:
      - 'http.title:"MCP Inspector"'
      - 'http.title:"OpenHands"'
      - 'http.title:"Cairn"'
      - 'http.title:"Strix"'
```

### Output Record (`./data/shodan.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"shodan:<12-hex-sha256>"` seeded by `ip|port|timestamp` (banners) or `query|total` (counts). |
| `event` | `{uuid, info, scanner: "shodan", mode, query, observed_at, collected_at}`. |
| `target` | `{url, domain, ip, port, asn}` populated from `ip_str`, `port`, `hostnames[0]`, and `asn` (or search URL for count records). |
| `http` | Full request/response metadata (`?key=***` redacted in `request_url`, banner text or JSON in `content` capped at 20,000 chars). |
| `attributes` | `url`, `domain`, `ip-dst`, `port`, `AS`, `sha256`, plus `x509-fingerprint-sha256` when TLS certificate metadata is present. |
| `tags` | `["shodan", "banner"]`, `["shodan", "count"]`, `["shodan", "host"]`, `["shodan", "dns"]`, or `["shodan", "alert"]`. |
| `raw` | Full upstream Shodan banner dictionary, count/facet object (`{total, facets}`), host profile, or DNS dictionary. |

---

## Examples

```sh
# 1. Incremental scan of configured targets over the last 7 days
shodan scan --json

# 2. Run all queries in config.yaml
shodan search --json

# 3. Explicit count + facet aggregation for a specific panel title
shodan search -q 'http.title:"MCP Inspector"' --count --facets org,country,port,asn --no-save --json

# 4. Banner search restricted to the last 7 days on page 1
shodan search -q 'http.title:"OpenHands"' --since-days 7 --page 1 --json

# 5. Direct host profile lookup with historical banners
shodan search --ip 45.14.13.147 --history --minify --json

# 6. DNS subdomain enumeration for a target domain
shodan search --domain stepfun-inc.com --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Count volatility** | Shodan crawls IP ranges asynchronously; dynamic cloud IPs rotate. | Treat +/-10% count swings as normal background churn; look for sudden clustering in a single ASN or port. |
| **Title / product collisions** | Generic short strings (`Cairn`, `Strix`) match unrelated web apps, marketing pages, or researcher honeypots. | Inspect `raw.http.html`, TLS certificate SANs (`x509-fingerprint-sha256`), and open API paths (`/mcp.json`, `/api/`). |
| **Login-gated vs. unauthenticated panels** | Most exposed web dashboards sit behind authentication walls or reverse proxies. | Prioritize hosts returning HTTP 200 on API/manifest routes or exposing unauthenticated task histories. |

---

## Self-Tests

```sh
shodan --self-test
uv run scanners/shodan/scan.py --self-test
uv run scanners/shodan/search.py --self-test
```
