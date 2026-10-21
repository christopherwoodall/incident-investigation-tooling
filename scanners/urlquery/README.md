# urlquery.net (`scanners/urlquery`)

Collects public URL sandbox submission reports, report details, and URL reputation checks from the urlquery.net Public REST API (`https://api.urlquery.net/public/v1`).

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (unseeded recent report polling across `window_hours`), `search` (query search, single report lookup, reputation check) |
| **Primary Endpoints** | `GET /public/v1/search/reports/`, `GET /public/v1/report/{report_id}`, `GET /public/v1/reputation/check/` |
| **Error Behavior** | Raises `RuntimeError("URLQUERY_API_KEY is required")` when `URLQUERY_API_KEY` is unset; fails loudly on HTTP errors |
| **Auth Env Var** | `URLQUERY_API_KEY` (required; sent via `X-Apikey` header, redacted to `"***"` in output records) |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `90.0s` / `3.0s` / `50` (`scan.window_hours`: `24`) |
| **Output File** | `./data/urlquery.jsonl` |
| **Emitted Tags** | `["urlquery", "report"]`, `["urlquery", "reputation"]` |
| **Upstream Docs** | [urlquery.net/help/search](https://urlquery.net/help/search) · [github.com/urlquery/urlquery-api-go](https://github.com/urlquery/urlquery-api-go) |

---

## History & Surface Context

urlquery.net executes submitted URLs inside instrumented browser sandboxes, recording full HTTP redirect chains, DOM loads, network transactions, and IDS/suricata alerts. Autonomous evaluation agents and researchers alike submit target URLs to urlquery.net to inspect page behavior or verify reachability, leaving query-parameter tags (`?uqscan=`, `?uqframe=`) and callback endpoints (`webhook.site`, `ntfy.sh`, `httpbin.org/base64/`) in the public submission index.

`urlquery scan` polls the global submission window (`date:[<cutoff> TO <now>]`) without requiring keyword seeds, whereas `urlquery search` sweeps the targeted indicator list in `scanners/config.yaml` or fetches individual report UUIDs.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
export URLQUERY_API_KEY="your-api-key"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners urlquery scan --json` | `scanners urlquery search --json` |
| **2. Console Alias** | `urlquery scan --json` | `urlquery search --json` |
| **3. `uv run` Script** | `uv run scanners/urlquery/scan.py --json` | `uv run scanners/urlquery/search.py --json` |
| **4. Direct Script** | `./scanners/urlquery/scan.py --json` | `./scanners/urlquery/search.py --json` |

---

## CLI Reference

### `urlquery scan` (`scanners/urlquery/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <query>` | `list[str]` | `urlquery.scan.targets` | Optional target filter combined with the date window (`<target> AND date:[...]`). |
| `--hours <float>` | `float` | `24.0` | Lookback window in hours when no prior `./data/urlquery.jsonl` timestamp exists. |
| `--limit <int>` | `int` | `50` | Maximum reports returned per scan query. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/urlquery.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `urlquery search` (`scanners/urlquery/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <query>` | `list[str]` | `urlquery.queries` | Repeatable urlquery search query string. |
| `-d`, `--domain <domain>` | `str` | `None` | Search reports by domain (`url.domain:<domain>`). |
| `--report-id <uuid>` | `str` | `None` | Fetch a full sandbox report by UUID (`/public/v1/report/{report_id}`). |
| `--reputation <url>` | `str` | `None` | Query URL reputation (`/public/v1/reputation/check/?query=<url>`). |
| `--limit <int>` | `int` | `50` | Maximum reports returned per search query. |
| `--offset <int>` | `int` | `0` | Pagination offset for `/public/v1/search/reports/`. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/urlquery.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/urlquery.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
urlquery:
  base_url: "https://api.urlquery.net/public/v1"
  api_key: "${oc.env:URLQUERY_API_KEY,''}"
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json"
  timeout: 90.0
  delay: 3.0
  limit: 50
  queries:
    - "uqscan="
    - "uqframe="
    - "webhook.site"
    - "ntfy.sh/amapdata"
    - "httpbin.org/base64/"
    - "url.domain:amap.com"
    - "pre-amap-pc-ssr.amap.com"
  scan:
    window_hours: 24
    targets: []
```

### Output Record (`./data/urlquery.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"urlquery:<12-hex-sha256>"` seeded by `urlquery|<report_id_or_url>` or `urlquery|reputation|<url>`. |
| `event` | `{uuid, info, scanner: "urlquery", mode, query, observed_at, collected_at}` (`observed_at` from `report.date`). |
| `target` | `{url, domain, ip, port: null, asn}` populated from `report.url.addr`, `report.url.domain`, `report.ip.addr`, and `report.ip.asn`. |
| `http` | Request/response telemetry with `X-Apikey: "***"` redacted in `request_headers`. |
| `attributes` | `url`, `domain`, `ip-dst`, `AS`, and `sha256` (`Payload delivery`). |
| `tags` | `["urlquery", "report"]` or `["urlquery", "reputation"]`. |
| `raw` | Untruncated urlquery report summary, full report payload (`--report-id`), or reputation check object (`--reputation`). |

---

## Examples

```sh
# 1. Poll newest public sandbox submissions from the last 24 hours
urlquery scan --json

# 2. Poll recent submissions filtered to a specific target keyword over 12 hours
urlquery scan -t "webhook.site" --hours 12 --limit 25 --json

# 3. Run all configured search queries in scanners/config.yaml
urlquery search --json

# 4. Search reports for a specific domain with pagination
urlquery search -d amap.com --limit 50 --offset 0 --json

# 5. Fetch a single full sandbox report by UUID
urlquery search --report-id 1446fb1c-8bf1-4bbe-9a83-ce0c5026499a --no-save --json

# 6. Check reputation status for a URL
urlquery search --reputation "https://goto.unm.edu/7t6-o" --no-save --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Shared utility noise** | Services like `webhook.site` and `httpbin.org` appear in benign developer testing, security tutorials, and phishing kits. | Require co-occurrence of multiple indicators (for example, a callback service paired with a harness query tag or target API path) during post-processing. |
| **Observer re-submissions** | Analysts frequently re-submit URLs published in threat reports to inspect them in urlquery.net. | Compare `event.observed_at` (`report.date`) against initial public disclosure dates and check whether the URL is an exact replay of a known sample. |

---

## Self-Tests

```sh
urlquery --self-test
uv run scanners/urlquery/scan.py --self-test
uv run scanners/urlquery/search.py --self-test
```
