# crt.sh Certificate Transparency (`scanners/crtsh`)

Queries Certificate Transparency (CT) logs via crt.sh (`https://crt.sh/?q=<pattern>&output=json&exclude=expired`) to enumerate TLS certificates and subdomains across operator infrastructure.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan`: Unsupported (warns on `stderr`, exits `0`); `search`: Supported (wildcard/domain CT search + `--issuer` filter) |
| **Primary Endpoint** | `GET https://crt.sh/?q=<pattern>&output=json&exclude=expired` |
| **Filtering & Error Behavior** | Filters known baseline serials (`BASELINE_SERIALS`); fails loudly on HTTP or JSON errors |
| **Auth Env Var** | None |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `90.0s` / `10.0s` / `100` (`scan.window_hours`: `720`) |
| **Output File** | `./data/crtsh.jsonl` |
| **Emitted Tags** | `["certificate", "crtsh", "search"]` |
| **Upstream Docs** | [crt.sh](https://crt.sh/) |

---

## History & Surface Context

Cloud sandboxes, agent gateways, and ephemeral container platforms issue per-instance or wildcard TLS certificates logged in public Certificate Transparency (CT) trees. Enumerating CT logs reveals container naming conventions (`%.hysandbox.tencent-cloud.com`), internal staging subdomains (`%.stepfun-inc.com`), and protocol surfaces (`%.x402.dev`).

Because crt.sh requires a domain or SQL wildcard pattern (`%`) and offers no unseeded firehose, `crtsh scan` is an intentional no-op stub (`SUPPORTED = False`).

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
```

| Method | `scan` Command (Stub) | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners crtsh scan` | `scanners crtsh search --json` |
| **2. Console Alias** | `crtsh scan` | `crtsh search --json` |
| **3. `uv run` Script** | `uv run scanners/crtsh/scan.py` | `uv run scanners/crtsh/search.py --json` |
| **4. Direct Script** | `./scanners/crtsh/scan.py` | `./scanners/crtsh/search.py --json` |

---

## CLI Reference

### `crtsh scan` (`scanners/crtsh/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--self-test` | `bool` | `False` | Verify `SUPPORTED is False` and `run_scan() == []`, then exit `0`. Any other invocation logs a warning to `stderr` and exits `0`. |

### `crtsh search` (`scanners/crtsh/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <pattern>` | `list[str]` | `crtsh.queries` | Repeatable crt.sh query pattern (for example, `%.stepfun-inc.com`). |
| `-d`, `--domain <domain>` | `str` | `None` | Target domain (automatically queries `%.<domain>`). |
| `--issuer <substring>` | `str` | `None` | Case-insensitive substring required in `issuer_name` (e.g., `"Let's Encrypt"`). |
| `--limit <int>` | `int` | `100` | Maximum certificate records emitted per query. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/crtsh.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/crtsh.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
crtsh:
  base_url: "https://crt.sh"
  api_key: ""
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/json"
  timeout: 90.0
  delay: 10.0
  limit: 100
  queries:
    - "%.hysandbox.tencent-cloud.com"
    - "%.stepfun-inc.com"
    - "%.x402.dev"
  scan:
    window_hours: 720
    targets: []
```

### Output Record (`./data/crtsh.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"crtsh:<12-hex-sha256>"` seeded by `crtsh|<serial_or_id>|<primary_domain>`. |
| `event` | `{uuid, info, scanner: "crtsh", mode: "search", query, observed_at, collected_at}` (`observed_at` from `entry_timestamp` or `not_before`). |
| `target` | `{url: "https://crt.sh/?id=<id>", domain: <primary_domain>, ip: null, port: null, asn: null}`. |
| `http` | Request/response metadata (`http.content` summarizes domain, serial, and issuer). |
| `attributes` | `url`, `domain`, `text` (`Other`, containing `Certificate serial <serial>`), and `sha256` (`Payload delivery`). |
| `tags` | `["certificate", "crtsh", "search"]`. |
| `raw` | Full CT log dictionary (`{id, issuer_name, common_name, name_value, entry_timestamp, not_before, not_after, serial_number}`). |

---

## Examples

```sh
# 1. Run all CT queries configured in scanners/config.yaml
crtsh search --json

# 2. Search non-expired certificates for a specific domain
crtsh search -d x402.dev --limit 25 --no-save --json

# 3. Search wildcard subdomains filtered to a specific Certificate Authority
crtsh search -q "%.stepfun-inc.com" --issuer "Let's Encrypt" --limit 50 --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **60-90 day automated renewals** | Let's Encrypt, ZeroSSL, and Google Trust Services automatically renew certificates every 60-90 days. | Check whether `raw.name_value` introduces a genuinely new hostname or simply renews an existing `common_name`. |
| **Baseline infrastructure serials** | Long-lived corporate wildcard certificates reappear on every query. | `search.py` automatically skips known static serials in `BASELINE_SERIALS` and deduplicates by `(serial_number, primary_domain)`. |
| **Multi-tenant wildcard certificates** | Shared cloud domains (`*.hysandbox.tencent-cloud.com`) cover thousands of unrelated customer sandboxes under a single wildcard cert. | Use CT logs to track subdomain and infrastructure provisioning rather than tenant-level attribution on wildcard certs. |

---

## Self-Tests

```sh
crtsh --self-test
uv run scanners/crtsh/scan.py --self-test
uv run scanners/crtsh/search.py --self-test
```
