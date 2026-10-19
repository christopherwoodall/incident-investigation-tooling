# Scanners

Self-contained [`uv`](https://docs.astral.sh/uv/guides/scripts/) scripts for collecting threat-intelligence telemetry. Each scanner directory contains one PEP 723 script (`scan.py`, <200 lines) and one YAML configuration file (`config.yaml`), and all scanners emit the exact same 12-field JSONL record shape.

## Layout

```text
scanners/
├── README.md
├── shodan/
│   ├── config.yaml      # Shodan runtime settings, regex patterns, and seeds
│   └── scan.py          # Shodan count / search / host scanner
├── urlquery/
│   ├── config.yaml      # urlquery.net runtime settings, regex patterns, and broad seeds
│   └── scan.py          # urlquery.net report search scanner
├── yourls/
│   ├── config.yaml      # Passive YOURLS/shortlink settings, regex patterns, and seeds
│   └── scan.py          # Passive YOURLS '+' stats page scanner
└── jina/
    ├── config.yaml      # Jina AI reader (r.jina.ai) settings, regex patterns, and seeds
    └── scan.py          # Jina AI reader text-extraction scanner
```

Output is appended to `./data/<scanner>.jsonl` at the repository root (git-ignored).

---

## Config Schema (`config.yaml`)

Every scanner uses the same three top-level sections:

```yaml
scanner:
  base_url: "https://api.urlquery.net/public/v1"
  api_key: "${oc.env:URLQUERY_API_KEY,''}"
  timeout: 90
  delay: 3.0
  max_runtime: 300
  max_results: 30
  since_hours: 24
  data_dir: "../../data"

patterns:
  tag_param: '(?:uqscan|uqframe|uqtag|uq|zz)=([a-zA-Z0-9_-]+)'
  webhook_uuid: 'webhook\.site/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
  ntfy_topic: 'ntfy\.sh/([a-zA-Z0-9_-]{3,64})'

seeds:
  - { name: uqscan_param, query: "uqscan=", tags: [harness, tag_grammar] }
  - { name: webhook_site, query: "webhook.site", tags: [exfil, webhook] }
```

- **`scanner`**: Runtime settings (`base_url`, `api_key`, `timeout`, `delay`, `max_runtime`, `since_hours`, `data_dir`).
- **`patterns`**: Flat `name: 'regex'` dictionary evaluated against every response to extract IOCs, callback UUIDs, agent labels, and parameters into `matches`.
- **`seeds`**: Broad, atomic queries (`name`, `query`, optional `op`, `tags`) executed against the upstream source.

---

## Unified Output Shape

All four scanners emit the exact same 12-field JSON object (via `--json` and in `./data/<scanner>.jsonl`):

```json
{
  "id": "urlquery:9f4c2a1b8e0d",
  "scanner": "urlquery",
  "seed": "uqscan_param",
  "query": "uqscan= date:[2026-04-12 TO 2026-04-13]",
  "observed_at": "2026-04-13T18:30:00Z",
  "url": "https://example.org/?uqscan=claude20261019",
  "ip": "203.0.113.5",
  "domain": "example.org",
  "status": 200,
  "matches": {
    "tag_param": ["claude20261019"],
    "webhook_uuid": ["12345678-1234-1234-1234-1234567890ab"]
  },
  "tags": ["harness", "tag_grammar", "tag_param", "webhook_uuid"],
  "raw": {}
}
```

---

## Usage

### Environment Variables

Set API keys in `.env` at the repository root or in your shell environment:

```bash
export SHODAN_API_KEY="your-shodan-key"
export URLQUERY_API_KEY="your-urlquery-key"
export JINA_API_KEY="your-optional-jina-key"
```

### Common CLI Flags

All four scanners support the same core flags:

- `-k <kw>`, `--keyword <kw>`: Run a keyword lookup (or highlight keyword matches in responses). Add `--filter-seeds` to filter configured YAML seeds by keyword.
- `--tag <tag>`: Run only seeds matching `<tag>` (repeatable).
- `--since-hours <N>` / `--since-days <N>` / `--from-date YYYY-MM-DD` / `--to-date YYYY-MM-DD`: Time-box queries or filter observations.
- `--max-runtime <sec>`: Hard wall-clock deadline for the scan run.
- `--list-seeds` / `--dry-run`: Print selected seeds as JSON without network calls.
- `--json`: Print unified 12-field JSON records to stdout.
- `--self-test`: Run offline self-tests.

### Examples

```bash
# Run offline self-tests across all scanners
uv run scanners/shodan/scan.py --self-test
uv run scanners/urlquery/scan.py --self-test
uv run scanners/yourls/scan.py --self-test
uv run scanners/jina/scan.py --self-test

# Inspect seeds without network calls
uv run scanners/urlquery/scan.py --list-seeds

# Keyword & time-boxed scans
uv run scanners/shodan/scan.py -k "MCP Inspector" --since-days 7 --json
uv run scanners/urlquery/scan.py --tag exfil --since-hours 24 --json
uv run scanners/yourls/scan.py -k "webhook.site" --from-date 2026-04-01 --json
uv run scanners/jina/scan.py -u "https://goto.unm.edu/7t6-o+" -k "claude" --json
```
