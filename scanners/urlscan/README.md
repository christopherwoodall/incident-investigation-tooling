# urlscan.io (`scanners/urlscan`)

Collects public sandbox scan submissions, DOM/network metadata, and full scan result documents from the urlscan.io REST API v1 (`https://urlscan.io/api/v1`).

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (polls recent scans matching `scan.targets`, default `date:>now-1h`), `search` (Elasticsearch query syntax + single result `--uuid` lookup) |
| **Primary Endpoints** | `GET /api/v1/search/?q=<query>&size=<limit>`, `GET /api/v1/result/<uuid>/` |
| **Automatic Fallback** | Works unauthenticated for public search queries; attaches `API-Key` header (redacted to `"***"` in output records) when `URLSCAN_API_KEY` is set |
| **Auth Env Var** | `URLSCAN_API_KEY` (optional for public search; recommended for higher rate limits and private visibility searches) |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `45.0s` / `2.0s` / `100` (`scan.window_hours`: `1`) |
| **Output File** | `./data/urlscan.jsonl` |
| **Emitted Tags** | `["result", "scan", "urlscan"]` (`scan`), `["result", "search", "urlscan"]` (`search`) |
| **Upstream Docs** | [urlscan.io/docs/api](https://urlscan.io/docs/api/) · [urlscan.io/docs/search](https://urlscan.io/docs/search/) |

---

## History & Surface Context

urlscan.io indexes URL submissions, resolved IPs, ASNs, TLS certificates, DOM hashes, and outgoing HTTP requests across millions of public browser sandbox executions. When autonomous agents or analysts submit URLs containing harness query tags (`uqscan=`, `uqframe=`), target API paths (`getPoiInfo`), sandbox container domains (`hysandbox.tencent-cloud.com`), or callback endpoints (`webhook.site`), urlscan.io preserves the full transaction graph.

`urlscan scan` polls recent public submissions using the Elasticsearch time filter in `urlscan.scan.targets` (`date:>now-1h`), while `urlscan search` runs targeted Elasticsearch queries (`page.url:`, `page.domain:`, `page.ip:`) or retrieves complete scan results via `--uuid`.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
# Optional: set URLSCAN_API_KEY for higher rate quotas
export URLSCAN_API_KEY="your-api-key"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners urlscan scan --json` | `scanners urlscan search --json` |
| **2. Console Alias** | `urlscan scan --json` | `urlscan search --json` |
| **3. `uv run` Script** | `uv run scanners/urlscan/scan.py --json` | `uv run scanners/urlscan/search.py --json` |
| **4. Direct Script** | `./scanners/urlscan/scan.py --json` | `./scanners/urlscan/search.py --json` |

---

## CLI Reference

### `urlscan scan` (`scanners/urlscan/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <query>` | `list[str]` | `urlscan.scan.targets` | Repeatable scan query override (default: `date:>now-1h`). |
| `--limit <int>` | `int` | `100` | Maximum search hits returned per target query (`size` parameter). |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/urlscan.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `urlscan search` (`scanners/urlscan/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <query>` | `list[str]` | `urlscan.queries` | Repeatable urlscan.io Elasticsearch query string. |
| `-d`, `--domain <domain>` | `str` | `None` | Search by page domain (`page.domain:<domain>`). |
| `--ip <ip>` | `str` | `None` | Search by resolved page IP address (`page.ip:<ip>`). |
| `--uuid <uuid>` | `str` | `None` | Fetch a full scan result JSON document via `/api/v1/result/<uuid>/`. |
| `--limit <int>` | `int` | `100` | Maximum search hits returned per query (`size` parameter). |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/urlscan.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/urlscan.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
urlscan:
  base_url: "https://urlscan.io/api/v1"
  api_key: "${oc.env:URLSCAN_API_KEY,''}"
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json"
  timeout: 45.0
  delay: 2.0
  limit: 100
  queries:
    - 'page.url:"uqscan="'
    - 'page.url:"uqframe="'
    - 'page.url:"getPoiInfo"'
    - 'page.domain:"hysandbox.tencent-cloud.com"'
    - 'page.domain:"webhook.site"'
  scan:
    window_hours: 1
    targets:
      - "date:>now-1h"
```

### Output Record (`./data/urlscan.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"urlscan:<12-hex-sha256>"` seeded by `urlscan|<task.uuid>` (or `urlscan|uuid|<uuid>`). |
| `event` | `{uuid, info, scanner: "urlscan", mode, query, observed_at, collected_at}` (`observed_at` from `task.time`). |
| `target` | `{url, domain, ip, port: null, asn}` populated from `page.url` (or `task.url`), `page.domain`, `page.ip`, and `page.asn`. |
| `http` | Request/response telemetry (`API-Key: "***"` redacted when configured). |
| `attributes` | `url`, `domain`, `ip-dst`, `AS`, and `sha256` (`Payload delivery`). |
| `tags` | `["result", "scan", "urlscan"]` or `["result", "search", "urlscan"]`. |
| `raw` | Full urlscan search hit object (`{task, page, stats, _id, result, screenshot}`) or full `/result/<uuid>/` document. |

---

## Examples

```sh
# 1. Poll recent public scans from the last hour (urlscan.scan.targets)
urlscan scan --limit 50 --json

# 2. Poll recent scans matching a custom Elasticsearch target filter
urlscan scan -t 'page.url:"uqscan=" AND date:>now-24h' --limit 25 --json

# 3. Run all search queries configured in scanners/config.yaml
urlscan search --json

# 4. Search scans for a specific domain or IP address
urlscan search -d hysandbox.tencent-cloud.com --limit 20 --json
urlscan search --ip 45.14.13.147 --json

# 5. Fetch the complete DOM/network result document for a specific scan UUID
urlscan search --uuid 0195f3a8-1234-7000-8000-000000000001 --no-save --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Automated PhishTank / CERT feeds** | Security feeds continuously submit thousands of unrelated URLs (including `webhook.site` phishing lures) to urlscan.io. | Filter on `raw.task.source`, `raw.task.tags`, and specific URL path patterns rather than treating domain-level hits on shared services as standalone incidents. |
| **Redirected final `page.domain`** | If a shortlink redirects to a benign landing page, `page.domain` reflects the final destination while `task.url` holds the initial shortlink. | Query `task.url:` or `page.url:` when hunting initial submission links, and inspect `raw.task.url` alongside `raw.page.url`. |

---

## Self-Tests

```sh
urlscan --self-test
uv run scanners/urlscan/scan.py --self-test
uv run scanners/urlscan/search.py --self-test
```
