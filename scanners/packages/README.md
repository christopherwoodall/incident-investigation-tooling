# Package Registries (`scanners/packages`)

Monitors the PyPI RSS updates feed and RubyGems recent updates feed (`scan.py`) and searches RubyGems, npm, and PyPI package metadata (`search.py`) for agent harnesses, sandbox packages, and indicator strings.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (polls `pypi.org/rss/updates.xml` and `rubygems.org/api/v1/activity/just_updated.json`), `search` (queries RubyGems search, npm search, and PyPI exact package JSON) |
| **Primary Endpoints** | `GET https://pypi.org/rss/updates.xml`, `GET https://rubygems.org/api/v1/activity/just_updated.json`, `GET https://rubygems.org/api/v1/search.json?query=<q>`, `GET https://registry.npmjs.org/-/v1/search?text=<q>&size=<n>`, `GET https://pypi.org/pypi/<pkg>/json` |
| **Automatic Fallback** | Parses the complete upstream XML/JSON response body (`full_text`) in memory before truncating `http.content` to the `20,000`-character storage cap |
| **Auth Env Var** | None |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `45.0s` / `2.0s` / `50` (`scan.window_hours`: `24`) |
| **Output File** | `./data/packages.jsonl` |
| **Emitted Tags** | `["packages", "pypi_rss", "scan"]`, `["packages", "rubygems_recent", "scan"]`, `["packages", "rubygems", "search"]`, `["packages", "npm", "search"]`, `["packages", "pypi", "search"]` |
| **Upstream Docs** | [guides.rubygems.org/rubygems-org-api](https://guides.rubygems.org/rubygems-org-api/) · [docs.pypi.org/api/json](https://docs.pypi.org/api/json/) · [npm Registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) |

---

## History & Surface Context

Autonomous agents and developer harnesses (`hysandbox-ats`, `oai-client`, MCP servers) publish and consume packages across RubyGems, npm, and PyPI. In trajectory investigations, custom gems (`hysandbox-ats` on `rubygems.org`) and internal client packages were queried or installed directly from public registries.

`packages scan` polls the live PyPI RSS feed (`pypi.org/rss/updates.xml`) and RubyGems activity stream (`rubygems.org/api/v1/activity/just_updated.json`) for newly updated releases, while `packages search` sweeps all three registries (`rubygems`, `npm`, `pypi`) for indicator strings and exact package names. Because `just_updated.json` exceeds 45 KB, `packages/scan.py` parses the full response payload before applying the 20,000-character `http.content` cap.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners packages scan --json` | `scanners packages search --json` |
| **2. Console Alias** | `packages scan --json` | `packages search --json` |
| **3. `uv run` Script** | `uv run scanners/packages/scan.py --json` | `uv run scanners/packages/search.py --json` |
| **4. Direct Script** | `./scanners/packages/scan.py --json` | `./scanners/packages/search.py --json` |

---

## CLI Reference

### `packages scan` (`scanners/packages/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <url>` | `list[str]` | `packages.scan.targets` | Repeatable feed URL override (supports PyPI RSS XML and RubyGems JSON feeds). |
| `--limit <int>` | `int` | `50` | Maximum items emitted per feed. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/packages.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `packages search` (`scanners/packages/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <query>` | `list[str]` | `packages.queries` | Repeatable package search query or exact package name. |
| `--package <name>` | `str` | `None` | Exact package name to look up across selected registries. |
| `--registry <choice>` | `str` | `"all"` | Registry filter: `all`, `rubygems`, `npm`, or `pypi`. |
| `--limit <int>` | `int` | `50` | Maximum results emitted per registry per query. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/packages.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/packages.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
packages:
  base_url: "https://rubygems.org/api/v1"
  api_key: ""
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json, application/rss+xml, text/xml"
  timeout: 45.0
  delay: 2.0
  limit: 50
  queries:
    - "hysandbox-ats"
    - "uqscan"
    - "getpoiinfo"
    - "oai-client"
  scan:
    window_hours: 24
    targets:
      - "https://pypi.org/rss/updates.xml"
      - "https://rubygems.org/api/v1/activity/just_updated.json"
```

### Output Record (`./data/packages.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"packages:<12-hex-sha256>"` seeded by `packages|pypi_rss|<link>`, `packages|rubygems_recent|<name>|<version>`, `packages|rubygems|<name>|<version>`, `packages|npm|<name>|<version>`, or `packages|pypi|<name>|<version>`. |
| `event` | `{uuid, info, scanner: "packages", mode, query, observed_at, collected_at}` (`observed_at` from RSS `pubDate` or npm `date`). |
| `target` | `{url, domain: "pypi.org" \| "rubygems.org" \| "www.npmjs.com", ip: null, port: null, asn: null}`. |
| `http` | Request/response telemetry (`http.content` holds `title — description` or `name version description`). |
| `attributes` | `url` (`Network activity`), `domain` (`Network activity`), and `sha256` (`Payload delivery`). |
| `tags` | `["packages", "pypi_rss", "scan"]`, `["packages", "rubygems_recent", "scan"]`, `["packages", "rubygems", "search"]`, `["packages", "npm", "search"]`, or `["packages", "pypi", "search"]`. |
| `raw` | RSS item (`{title, link, pubDate, description}`), RubyGems gem object, npm search `package` object, or PyPI `info` dictionary (`{name, version, summary, author, home_page, package_url}`). |

---

## Examples

```sh
# 1. Poll PyPI RSS updates and RubyGems just_updated activity stream
packages scan --limit 15 --json

# 2. Run all package queries configured in scanners/config.yaml across RubyGems, npm, and PyPI
packages search --json

# 3. Look up an exact package on PyPI only
packages search --package mcp --registry pypi --no-save --json

# 4. Search RubyGems or npm for a keyword
packages search -q "hysandbox-ats" --registry rubygems --json
packages search -q "mcp-inspector" --registry npm --limit 10 --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Unfiltered global activity feeds** | `packages scan` ingests the global PyPI and RubyGems update streams, where most releases are routine open-source updates. | Filter `./data/packages.jsonl` downstream with `rg` or `jq` for agent keywords, sandbox prefixes (`hysandbox`), or suspicious author metadata. |
| **PyPI exact-name lookup vs. RubyGems/npm search** | PyPI disabled its unauthenticated keyword search endpoint; `search.py` queries exact PyPI package metadata (`/pypi/<name>/json`) while running full keyword searches on RubyGems and npm. | Use `--registry npm` or `--registry rubygems` for substring discovery, and pass exact package names when checking `--registry pypi`. |

---

## Self-Tests

```sh
packages --self-test
uv run scanners/packages/scan.py --self-test
uv run scanners/packages/search.py --self-test
```
