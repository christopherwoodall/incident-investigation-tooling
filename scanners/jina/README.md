# Jina Reader & Search (`scanners/jina`)

Fetches and converts target web pages into clean Markdown via Jina Reader (`https://r.jina.ai/<url>` in `scan.py`) and executes web searches via Jina Search (`https://s.jina.ai/<query>` in `search.py`).

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (fetches and renders target URLs via `r.jina.ai`), `search` (executes web queries via `s.jina.ai`) |
| **Primary Endpoints** | `GET https://r.jina.ai/<target_url>` (`scan.py`), `GET https://s.jina.ai/<query>` (`search.py`) |
| **Error Behavior** | Fails loudly on HTTP transport or status errors (`HTTPError`, `URLError`) |
| **Auth Env Var** | `JINA_API_KEY` (optional; sent as `Authorization: Bearer ***`, redacted in output records) |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `120.0s` / `5.0s` / `50` (`scan.window_hours`: `24`) |
| **Output File** | `./data/jina.jsonl` |
| **Emitted Tags** | `["jina", "reader"]` (`scan`), `["jina", "s_jina"]` (`search`) |
| **Upstream Docs** | [jina.ai/reader](https://jina.ai/reader/) · [github.com/jina-ai/reader](https://github.com/jina-ai/reader) |

---

## History & Surface Context

Autonomous agents frequently use `r.jina.ai` and `s.jina.ai` to read web pages and search the web in LLM-ready Markdown, and investigators use the same endpoints to snapshot live agent manifests (`llms.txt`, `skill.md`, `mcp.json`, `CROSS_SITE_CONNECTIONS.md`) and shortener stats pages without running a local headless browser.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
# Optional: set JINA_API_KEY for higher rate limits and direct s.jina.ai JSON arrays
export JINA_API_KEY="your-api-key"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners jina scan --json` | `scanners jina search --json` |
| **2. Console Alias** | `jina scan --json` | `jina search --json` |
| **3. `uv run` Script** | `uv run scanners/jina/scan.py --json` | `uv run scanners/jina/search.py --json` |
| **4. Direct Script** | `./scanners/jina/scan.py --json` | `./scanners/jina/search.py --json` |

---

## CLI Reference

### `jina scan` (`scanners/jina/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-u`, `--url <url>` | `list[str]` | `jina.scan.targets` | Repeatable target URL to fetch and render via `https://r.jina.ai/<url>`. |
| `--limit <int>` | `int` | `50` | Maximum target URLs fetched per scan run. |
| `--respond-with <mode>` | `str` | `None` | Set Jina `X-Respond-With` header (`markdown`, `html`, `text`, `screenshot`). |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/jina.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `jina search` (`scanners/jina/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <query>` | `list[str]` | `jina.queries` | Repeatable web search query string. |
| `--site <domain>` | `str` | `None` | Restrict `s.jina.ai` search to a specific domain via the `X-Site` header. |
| `--limit <int>` | `int` | `50` | Maximum search result records emitted per query. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/jina.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/jina.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
jina:
  base_url: "https://s.jina.ai"
  api_key: "${oc.env:JINA_API_KEY,''}"
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json"
  timeout: 120.0
  delay: 5.0
  limit: 50
  queries:
    - "uqscan webhook.site"
    - "hysandbox.tencent-cloud.com"
    - "amapdata-b0g3lmf2g1"
    - "MCP Inspector mcp.json"
  scan:
    window_hours: 24
    targets:
      - "https://goto.unm.edu/7t6-o+"
      - "https://agentgateway.pythonanywhere.com/mcp.json"
      - "https://agentsboard.org/llms.txt"
      - "https://agents-agents-agents.com/llms.txt"
      - "https://bboard.ai/llms.txt"
      - "https://tantive.space/skill.md"
      - "https://she-llac.com/CROSS_SITE_CONNECTIONS.md"
      - "https://rentahuman.ai/api/bounties"
```

### Output Record (`./data/jina.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"jina:<12-hex-sha256>"` seeded by `jina|reader|<target_url>|<content_sha256>` (`scan`) or `jina|search|<query>|<result_url_or_sha256>` (`search`). |
| `event` | `{uuid, info, scanner: "jina", mode, query, observed_at, collected_at}` (`observed_at` from `publishedTime` when available). |
| `target` | `{url, domain, ip: null, port: null, asn: null}` for the rendered page or search hit URL. |
| `http` | Request/response metadata (`Authorization: "***"` redacted) and rendered Markdown/text in `http.content` (up to `20,000` chars). |
| `attributes` | `url` (`Network activity`), `domain` (`Network activity`), and `sha256` (`Payload delivery`). |
| `tags` | `["jina", "reader"]` (`scan`) or `["jina", "s_jina"]` (`search`). |
| `raw` | Jina `data` object (`{title, url, content, description, publishedTime}`) or fallback metadata (`{reader_url, bytes}`). |

---

## Examples

```sh
# 1. Fetch and render all target URLs in jina.scan.targets via r.jina.ai
jina scan --json

# 2. Grab a single URL in plain text format without persisting to ./data/jina.jsonl
jina scan -u "https://agentsboard.org/llms.txt" --respond-with text --no-save --json

# 3. Run all web search queries in jina.queries via s.jina.ai
jina search --json

# 4. Run an ad-hoc web search restricted to a single domain
jina search -q "mcp.json" --site github.com --limit 10 --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Reader wrapper text** | `r.jina.ai` prepends `Title:`, `URL Source:`, and `Markdown Content:` headers and replaces images with `![Image N]` placeholders. | Match content indicators against `http.content` or `raw.content` while ignoring Jina wrapper prefixes. |
| **Security writeups vs. live surfaces** | Web search results for indicator strings often return threat-intelligence blogs, GitHub issues, or documentation discussing the indicator. | Inspect `target.domain` and `target.url` to distinguish secondary reporting from primary infrastructure (`llms.txt`, `skill.md`, `mcp.json`, shorteners, or paste sites). |

---

## Self-Tests

```sh
jina --self-test
uv run scanners/jina/scan.py --self-test
uv run scanners/jina/search.py --self-test
```
