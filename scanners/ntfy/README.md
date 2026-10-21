# ntfy.sh Dead-Drop Channels (`scanners/ntfy`)

Polls public ntfy.sh pub/sub notification topics (`https://ntfy.sh/<topic>/json?poll=1&since=<since>`) for cached messages.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan`: Unsupported (warns on `stderr`, exits `0`); `search`: Supported (polls topic list with `since=all`) |
| **Primary Endpoint** | `GET https://ntfy.sh/<topic>/json?poll=1&since=<since>` |
| **Error Behavior** | Fails loudly on HTTP transport or status errors (`HTTPError`, `URLError`) |
| **Auth Env Var** | None |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `25.0s` / `3.0s` / `50` (`scan.window_hours`: `12`) |
| **Output File** | `./data/ntfy.jsonl` |
| **Emitted Tags** | `["message", "ntfy", "search"]` |
| **Upstream Docs** | [docs.ntfy.sh/subscribe/api](https://docs.ntfy.sh/subscribe/api/) |

---

## History & Surface Context

`ntfy.sh` is an unauthenticated HTTP pub/sub service where any client can publish a message (`POST https://ntfy.sh/<topic>`) and any subscriber can read cached messages (`GET https://ntfy.sh/<topic>/json?poll=1&since=all`) without creating an account. Autonomous evaluation agents have used topic slugs (`amapdata-b0g3lmf2g1-0429`, `c6836`, `kz1wu398dnq`, `mha3x`, `o54445`, `pz4kopsh1`) as lightweight exfiltration and coordination dead drops.

Because `ntfy.sh` exposes no public directory of active topics, `ntfy scan` is an intentional no-op stub (`SUPPORTED = False`). For historical snapshots of expired `ntfy.sh` topics, query `wayback search` directly.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
```

| Method | `scan` Command (Stub) | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners ntfy scan` | `scanners ntfy search --json` |
| **2. Console Alias** | `ntfy scan` | `ntfy search --json` |
| **3. `uv run` Script** | `uv run scanners/ntfy/scan.py` | `uv run scanners/ntfy/search.py --json` |
| **4. Direct Script** | `./scanners/ntfy/scan.py` | `./scanners/ntfy/search.py --json` |

---

## CLI Reference

### `ntfy scan` (`scanners/ntfy/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--self-test` | `bool` | `False` | Verify `SUPPORTED is False` and `run_scan() == []`, then exit `0`. Any other invocation logs a warning to `stderr` and exits `0`. |

### `ntfy search` (`scanners/ntfy/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--topic <topic>` | `list[str]` | `ntfy.queries` | Repeatable ntfy.sh topic name to poll. |
| `-q`, `--query <topic>` | `list[str]` | `None` | Alias for `--topic`. |
| `--since <duration>` | `str` | `"all"` | ntfy `since` parameter (`all`, `12h`, `30m`, or Unix epoch timestamp). |
| `--limit <int>` | `int` | `50` | Maximum messages emitted per topic. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/ntfy.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/ntfy.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
ntfy:
  base_url: "https://ntfy.sh"
  api_key: ""
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/x-ndjson, application/json"
  timeout: 25.0
  delay: 3.0
  limit: 50
  queries:
    - "amapdata-b0g3lmf2g1-0429"
    - "c6836"
    - "kz1wu398dnq"
    - "mha3x"
    - "o54445"
    - "pz4kopsh1"
  scan:
    window_hours: 12
    targets: []
```

### Output Record (`./data/ntfy.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"ntfy:<12-hex-sha256>"` seeded by `ntfy|<topic>|<msg_id>`. |
| `event` | `{uuid, info, scanner: "ntfy", mode: "search", query, observed_at, collected_at}` (`observed_at` from Unix `time`). |
| `target` | `{url: "https://ntfy.sh/<topic>", domain: "ntfy.sh", ip: null, port: null, asn: null}`. |
| `http` | Request/response telemetry; `http.content` holds the message text and title. |
| `attributes` | `url`, `domain`, and `sha256` (`Payload delivery`). |
| `tags` | `["message", "ntfy", "search"]`. |
| `raw` | Full ntfy message object (`{id, time, event: "message", topic, message, title, tags, priority}`). |

---

## Examples

```sh
# 1. Poll all topics configured in scanners/config.yaml
ntfy search --json

# 2. Poll a specific topic over the last 12 hours without saving to disk
ntfy search -t amapdata-b0g3lmf2g1-0429 --since 12h --no-save --json

# 3. Poll multiple topics via -t / -q with a 10-message limit
ntfy search -t c6836 -q kz1wu398dnq --limit 10 --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Short topic name collisions** | Short or dictionary topics (`test`, `alerts`, `c6836`) can be written to by unrelated home-lab users or CI scripts. | Prioritize high-entropy topic slugs (`amapdata-b0g3lmf2g1-0429`) or require structured JSON/base64 payloads inside `raw.message`. |
| **Unauthenticated spoofing** | Anyone who knows a topic name can `POST` arbitrary messages to it, including researchers testing a published indicator. | Compare message timestamps (`event.observed_at`) against public disclosure dates and look for corroborating sandbox or archive records. |

---

## Self-Tests

```sh
ntfy --self-test
uv run scanners/ntfy/scan.py --self-test
uv run scanners/ntfy/search.py --self-test
```
