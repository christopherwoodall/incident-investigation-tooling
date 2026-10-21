# YOURLS (`scanners/yourls`)

Collects raw HTML and JSON telemetry from public YOURLS link-shortener instances, `+` stats pages (`https://<host>/<slug>+`), sitemaps, and `yourls-api.php` endpoints.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (polls discovery feeds in `scan.targets`), `search` (fetches `<shorturl>+` stats pages and `yourls-api.php` endpoints) |
| **Primary Endpoints** | `GET https://<host>/<slug>+`, `GET https://<host>/sitemap.xml`, `GET https://<host>/yourls-api.php?action=<action>&format=json` |
| **Automatic Fallback** | In `search.py`, waits `1.25s` and retries once when an initial HTTP 200 response is `<500` bytes (university anti-bot interstitial) |
| **Auth Env Var** | None (optional `--signature` flag supported for authenticated `yourls-api.php` instances) |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `45.0s` / `3.0s` / `50` (`scan.window_hours`: `24`) |
| **Output File** | `./data/yourls.jsonl` |
| **Emitted Tags** | `["yourls", "discovery"]` (`scan`), `["yourls", "stats"]` (`search`) |
| **Upstream Docs** | [yourls.org/docs](https://yourls.org/docs) · [yourls.org/docs/guide/advanced/api](https://yourls.org/docs/guide/advanced/api) |

---

## History & Surface Context

YOURLS (Your Own URL Shortener) exposes public click-statistics pages whenever `+` is appended to a shortlink (`https://<host>/<slug>+`), revealing the full destination URL, creation timestamp, click history, and referrer metadata. Several open or semi-open instances also expose `/sitemap.xml` or unauthenticated `yourls-api.php?action=stats&format=json` endpoints that list recently created shortlinks.

In autonomous agent investigations, public shorteners (`goto.unm.edu`, `t.mdcdev.me`, `yourls.space`, `u.ethz.ch`, `go.uvm.edu`, and `url.popcat.xyz`) were used to wrap redirect chains, obfuscate callback URLs, and track link clicks. `yourls scan` polls root pages, sitemaps, and stats APIs for new links, while `yourls search` retrieves individual `+` stats pages and API actions.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners yourls scan --json` | `scanners yourls search --json` |
| **2. Console Alias** | `yourls scan --json` | `yourls search --json` |
| **3. `uv run` Script** | `uv run scanners/yourls/scan.py --json` | `uv run scanners/yourls/search.py --json` |
| **4. Direct Script** | `./scanners/yourls/scan.py --json` | `./scanners/yourls/search.py --json` |

---

## CLI Reference

### `yourls scan` (`scanners/yourls/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <url>` | `list[str]` | `yourls.scan.targets` | Repeatable discovery target URL (root page, `sitemap.xml`, or `yourls-api.php` URL). |
| `--limit <int>` | `int` | `50` | Maximum discovery target URLs polled per scan. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/yourls.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `yourls search` (`scanners/yourls/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-u`, `--url <url>` | `list[str]` | `yourls.queries` | Repeatable shortlink stats URL (e.g., `https://goto.unm.edu/7t6-o+`) or API URL. |
| `--host <host>` | `str` | `None` | Target YOURLS hostname or base URL (e.g., `yourls.space` or `https://goto.unm.edu`). |
| `--shorturl <slug>` | `str` | `None` | Shortlink keyword on `--host` (e.g., `7t6-o`). |
| `--action <choice>` | `str` | `None` | Query `yourls-api.php` on `--host`: choices are `url-stats`, `expand`, `stats`, `db-stats`. |
| `--signature <token>` | `str` | `None` | Optional signature token for passwordless `yourls-api.php` authentication. |
| `--limit <int>` | `int` | `50` | Maximum URLs queried per run (also passed as `limit` when `--action stats` is used). |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/yourls.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/yourls.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
yourls:
  base_url: "https://goto.unm.edu"
  api_key: ""
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
  timeout: 45.0
  delay: 3.0
  limit: 50
  queries:
    - "https://goto.unm.edu/7t6-o+"
    - "https://goto.unm.edu/7t6-m+"
    - "https://t.mdcdev.me/squarespacefreeemail934785+"
    - "https://u.ethz.ch/31c3+"
    - "https://go.uvm.edu/00c+"
    - "https://url.popcat.xyz/oaitest123/info"
    - "https://url.popcat.xyz/oaicbs220/info"
  scan:
    window_hours: 24
    targets:
      - "https://t.mdcdev.me/"
      - "https://t.mdcdev.me/sitemap.xml"
      - "https://yourls.space/yourls-api.php?action=stats&format=json&filter=last&limit=100"
```

### Output Record (`./data/yourls.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"yourls:<12-hex-sha256>"` seeded by `yourls|scan|<url>|<content_sha256>` (`scan`) or `yourls|<url>` (`search`). |
| `event` | `{uuid, info, scanner: "yourls", mode, query, observed_at, collected_at}`. |
| `target` | `{url, domain, ip: null, port: null, asn: null}` for the polled shortener or API endpoint. |
| `http` | Full request/response headers, status code, `content_sha256`, and up to `20,000` chars of HTML/XML/JSON in `http.content`. |
| `attributes` | `url` (`Network activity`), `domain` (`Network activity`), and `sha256` (`Payload delivery`). |
| `tags` | `["yourls", "discovery"]` (`scan`) or `["yourls", "stats"]` (`search`). |
| `raw` | Parsed JSON dictionary when the endpoint returns JSON (`yourls-api.php` or `url.popcat.xyz`), or `{"bytes": <int>}` for HTML/XML responses. |

---

## Examples

```sh
# 1. Poll configured discovery feeds (root pages, sitemaps, and yourls-api.php stats)
yourls scan --json

# 2. Sweep all configured '+' stats pages in scanners/config.yaml
yourls search --json

# 3. Inspect a single shortlink '+' stats page without writing to disk
yourls search -u "https://goto.unm.edu/7t6-o+" --no-save --json

# 4. Query yourls-api.php for recent shortlink stats on an open instance
yourls search --host "https://yourls.space" --action stats --limit 50 --json

# 5. Expand or fetch url-stats for a specific slug via yourls-api.php
yourls search --host "goto.unm.edu" --shorturl "7t6-o" --action url-stats --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Anti-bot interstitials** | University hosts occasionally return a `<500` byte challenge page on the first uncached request. | `search.py` automatically pauses `1.25s` and retries once; verify `http.content_length > 500` when reviewing HTML stats captures. |
| **Authenticated vs. anonymous instances** | Campus shorteners (`goto.unm.edu`, `u.ethz.ch`, `go.uvm.edu`) require institutional login to create links (while keeping `+` stats pages public), whereas open instances (`t.mdcdev.me`, `yourls.space`) allow anonymous creation. | Treat anonymous shorteners as noisy public surfaces; filter `http.content` and `raw` for specific destination domains, callback UUIDs, or harness parameters. |

---

## Self-Tests

```sh
yourls --self-test
uv run scanners/yourls/scan.py --self-test
uv run scanners/yourls/search.py --self-test
```
