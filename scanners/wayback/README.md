# Wayback Machine CDX (`scanners/wayback`)

Queries the Internet Archive Wayback Machine CDX Server API (`http://web.archive.org/cdx/search/cdx`) for historical URL captures by domain, URL prefix, or wildcard pattern while filtering out crawler-induced anti-bot telemetry.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan`: Unsupported (warns on `stderr`, exits `0`); `search`: Supported (CDX prefix, domain, and wildcard queries) |
| **Primary Endpoint** | `GET http://web.archive.org/cdx/search/cdx?url=<pattern>&output=json&collapse=urlkey&limit=<limit>` |
| **Automatic Fallback** | Retries transient gateway errors or empty responses once after `2.5s`; strips anti-bot URLs matching `NOISE_SUBSTRINGS` |
| **Auth Env Var** | None |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `120.0s` / `5.0s` / `200` (`scan.window_hours`: `168`) |
| **Output File** | `./data/wayback.jsonl` |
| **Emitted Tags** | `["wayback", "cdx"]` |
| **Upstream Docs** | [archive.org/developers/wayback-cdx-server.html](https://archive.org/developers/wayback-cdx-server.html) · [github.com/internetarchive/wayback](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) |

---

## History & Surface Context

Web archives preserve historical URLs, query parameters, and redirect chains without contacting live operator infrastructure. When autonomous agents or their harnesses fetch URLs through archive save endpoints or public crawlers index dead-drop links, the full request URL (including query tags like `?uqscan=` or base64 reflector paths) is recorded in the CDX index.

Because the Wayback CDX API requires a domain or URL prefix and does not expose an unseeded global firehose, `wayback scan` is an intentional no-op stub (`SUPPORTED = False`). All collection runs through `wayback search`.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
```

| Method | `scan` Command (Stub) | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners wayback scan` | `scanners wayback search --json` |
| **2. Console Alias** | `wayback scan` | `wayback search --json` |
| **3. `uv run` Script** | `uv run scanners/wayback/scan.py` | `uv run scanners/wayback/search.py --json` |
| **4. Direct Script** | `./scanners/wayback/scan.py` | `./scanners/wayback/search.py --json` |

---

## CLI Reference

### `wayback scan` (`scanners/wayback/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--self-test` | `bool` | `False` | Verify `SUPPORTED is False` and `run_scan() == []`, then exit `0`. Any other invocation logs a warning to `stderr` and exits `0`. |

### `wayback search` (`scanners/wayback/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <pattern>` | `list[str]` | `wayback.queries` | Repeatable CDX `url` query pattern (supports `*` wildcards). |
| `-u`, `--url <prefix>` | `str` | `None` | Target URL or prefix for CDX lookup (sets `matchType=prefix` when no `*` is present). |
| `-d`, `--domain <domain>` | `str` | `None` | Target domain (expands to `*.<domain>/*`). |
| `--filter <expr>` | `str` | `None` | CDX `filter` expression (for example, `statuscode:200` or `!mimetype:image/.*`). |
| `--collapse <field>` | `str` | `"urlkey"` | CDX `collapse` deduplication field (`urlkey`, `digest`, `timestamp:8`). |
| `--limit <int>` | `int` | `200` | Maximum CDX rows returned per query. |
| `--from-date <YYYY-MM-DD>` | `str` | `None` | Start date filter (converted to `from=YYYYMMDD`). |
| `--to-date <YYYY-MM-DD>` | `str` | `None` | End date filter (converted to `to=YYYYMMDD`). |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/wayback.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/wayback.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
wayback:
  base_url: "http://web.archive.org/cdx/search/cdx"
  api_key: ""
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json"
  timeout: 120.0
  delay: 5.0
  limit: 200
  queries:
    - "*.hysandbox.tencent-cloud.com/*"
    - "pre-amap-pc-ssr.amap.com/*"
    - "amap-pc-ssr.amap.com/ssr/place/*"
    - "amap-pc-ssr.amap.com/ssr/api/getPoiInfo*"
    - "httpbin.org/base64/*"
    - "url.popcat.xyz/oai*"
  scan:
    window_hours: 168
    targets: []
```

### Output Record (`./data/wayback.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"wayback:<12-hex-sha256>"` seeded by `wayback|<cdx_timestamp>|<original_url>`. |
| `event` | `{uuid, info, scanner: "wayback", mode: "search", query, observed_at, collected_at}` (`observed_at` parsed from 14-digit CDX `timestamp`). |
| `target` | `{url: <original_url>, domain: <hostname>, ip: null, port: null, asn: null}`. |
| `http` | CDX request/response metadata; `http.content_type` stores the archived capture's `mimetype`, and `http.content` stores `original_url`. |
| `attributes` | `url` (`Network activity`), `domain` (`Network activity`), and `sha256` (`Payload delivery`). |
| `tags` | `["wayback", "cdx"]`. |
| `raw` | Full CDX row dictionary (`{urlkey, timestamp, original, mimetype, statuscode, digest, length, wayback_url}`). |

---

## Examples

```sh
# Run with `scanners` CLI
scanners wayback search --json

# Run with console alias
wayback search --json

# Run with `uv run` script
uv run scanners/wayback/search.py --json

# 1. Run all CDX queries configured in scanners/config.yaml
wayback search --json

# 2. Search all archived URLs under a domain and its subdomains
wayback search -d hysandbox.tencent-cloud.com --limit 100 --json

# 3. Search a URL prefix within a date range and status code filter
wayback search -u "httpbin.org/base64/" --from-date 2026-09-01 --to-date 2026-10-20 --filter "statuscode:200" --no-save --json

# 4. Run an ad-hoc wildcard query collapsed by content digest
wayback search -q "url.popcat.xyz/oai*" --collapse digest --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Crawler-induced anti-bot noise** | Archival crawlers frequently trigger anti-bot interstitials (`_____tmd_____`, `punish`, `secdev.alicdn.com`) when rendering dynamic pages. | `search.py` automatically drops URLs matching `NOISE_SUBSTRINGS` (`_____tmd_____`, `punishTextFetch`, `page/feedback`, `secdev.alicdn.com`). |
| **Archive presence vs. attribution** | A CDX row proves when a URL was archived, not who requested the capture. | Correlate CDX timestamps with embedded query tokens, unique callback IDs, or multi-surface bursts before attributing activity. |

---

## Self-Tests

```sh
wayback --self-test
uv run scanners/wayback/scan.py --self-test
uv run scanners/wayback/search.py --self-test
```
