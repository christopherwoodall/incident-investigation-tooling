# RepoScout (`scanners/reposcout`)

Enumerates recursive file trees across GitHub repositories (`/repos/{owner}/{repo}/git/trees/{branch}?recursive=1`) and Hugging Face datasets (`/api/datasets/{id}/tree/{branch}`) to discover trajectory logs, evaluation fixtures, and structured data files.

---

## Datasheet

| Field | Value |
| :--- | :--- |
| **Modes** | `scan` (diffs watched GitHub/Hugging Face file trees in `scan.targets`), `search` (enumerates candidate data files across `queries`, `--github`, or `--hf`) |
| **Primary Endpoints** | `GET https://api.github.com/repos/<owner>/<repo>/git/trees/<branch>?recursive=1`, `GET https://huggingface.co/api/datasets/<org>/<dataset>/tree/<branch>` |
| **Automatic Fallback** | Strips `Authorization` header automatically when querying `huggingface.co`; filters tree entries to `CANDIDATE_EXTENSIONS` (`.json`, `.jsonl`, `.parquet`, `.csv`, `.tsv`, `.yaml`, `.yml`, `.txt`, `.md`) |
| **Auth Env Var** | `GITHUB_TOKEN` (optional; raises GitHub REST API rate limit from 60 to 5,000 req/hr; redacted to `"***"` in output records) |
| **Default User-Agent** | Inherited from `defaults.user_agent` (`incident-investigation-scanners/1.0`) |
| **Timeout / Delay / Limit** | `30.0s` / `2.0s` / `200` (`scan.window_hours`: `24`) |
| **Output File** | `./data/reposcout.jsonl` |
| **Emitted Tags** | `["github", "reposcout", "scan"\|"search"]`, `["hf", "reposcout", "scan"\|"search"]` |
| **Upstream Docs** | [docs.github.com/en/rest/git/trees](https://docs.github.com/en/rest/git/trees) · [huggingface.co/docs/hub/api](https://huggingface.co/docs/hub/api) |

---

## History & Surface Context

Public agent benchmark repositories (`github:TIGER-AI-Lab/ClawBench`) and trace datasets (`hf:TIGER-Lab/ClawBenchV2Trace`) store thousands of execution trajectories, tool-call transcripts, and prompt fixtures containing real external URLs, sandbox domains, and dead-drop identifiers.

`reposcout` inspects repository and dataset file trees without cloning multi-gigabyte blobs locally. `reposcout scan` monitors watched repositories in `scan.targets` and emits records for newly added or modified candidate files (keyed by blob SHA/oid), while `reposcout search` queries arbitrary GitHub repos (`--github owner/repo`) and Hugging Face datasets (`--hf org/dataset`) with optional `--branch` and `--ext` filters.

---

## Installation & Ways to Run

```sh
# Editable install (from ./scanners)
cd scanners && uv venv && uv pip install -e ".[dev]"
# Optional: set GITHUB_TOKEN for 5,000 req/hr GitHub API quota
export GITHUB_TOKEN="ghp_your_token"
```

| Method | `scan` Command | `search` Command |
| :--- | :--- | :--- |
| **1. Central CLI** | `scanners reposcout scan --json` | `scanners reposcout search --json` |
| **2. Console Alias** | `reposcout scan --json` | `reposcout search --json` |
| **3. `uv run` Script** | `uv run scanners/reposcout/scan.py --json` | `uv run scanners/reposcout/search.py --json` |
| **4. Direct Script** | `./scanners/reposcout/scan.py --json` | `./scanners/reposcout/search.py --json` |

---

## CLI Reference

### `reposcout scan` (`scanners/reposcout/scan.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-t`, `--target <spec>` | `list[str]` | `reposcout.scan.targets` | Repeatable target specification (`github:<owner/repo>` or `hf:<org/dataset>`). |
| `--limit <int>` | `int` | `200` | Maximum candidate files emitted per target repository/dataset. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/reposcout.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

### `reposcout search` (`scanners/reposcout/search.py`)

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config <path>` | `Path` | `scanners/config.yaml` | Path to YAML configuration file. |
| `-q`, `--query <spec>` | `list[str]` | `reposcout.queries` | Repeatable target specification (`github:<owner/repo>` or `hf:<org/dataset>`). |
| `--github <owner/repo>` | `list[str]` | `None` | Repeatable GitHub repository slug (expands to `github:<owner/repo>`). |
| `--hf <org/dataset>` | `list[str]` | `None` | Repeatable Hugging Face dataset slug (expands to `hf:<org/dataset>`). |
| `--branch <rev>` | `str` | `"main"` | Git branch or revision to inspect. |
| `--ext <ext>` | `list[str]` | `CANDIDATE_EXTENSIONS` | Repeatable file extension filter (for example, `--ext .jsonl --ext .parquet`). |
| `--limit <int>` | `int` | `200` | Maximum candidate files emitted per repository/dataset. |
| `--new-only` | `bool` | `False` | Emit only records not yet present in `./data/reposcout.jsonl`. |
| `--user-agent <str>` | `str` | `defaults.user_agent` | Override the HTTP `User-Agent` request header. |
| `--header "Key: Value"` | `list[str]` | `[]` | Repeatable custom HTTP request header. |
| `--output <path>` | `Path` | `./data/reposcout.jsonl` | Override output JSONL file path. |
| `--no-save` | `bool` | `False` | Do not persist records to disk. |
| `--json` | `bool` | `False` | Print JSONL records to `stdout`. |
| `--self-test` | `bool` | `False` | Run offline self-test and exit `0`. |

---

## Data Shapes

### Input Configuration (`scanners/config.yaml`)

```yaml
reposcout:
  base_url: "https://api.github.com"
  api_key: "${oc.env:GITHUB_TOKEN,''}"
  user_agent: "${defaults.user_agent}"
  headers:
    Accept: "application/vnd.github+json, application/json"
  timeout: 30.0
  delay: 2.0
  limit: 200
  queries:
    - "github:TIGER-AI-Lab/ClawBench"
    - "hf:TIGER-Lab/ClawBenchV2Trace"
  scan:
    window_hours: 24
    targets:
      - "github:TIGER-AI-Lab/ClawBench"
      - "hf:TIGER-Lab/ClawBenchV2Trace"
```

### Output Record (`./data/reposcout.jsonl`)

| Key | Populated Fields & Behavior |
| :--- | :--- |
| `id` | `"reposcout:<12-hex-sha256>"` seeded by `reposcout|github|<repo>|<path>|<sha>` or `reposcout|hf|<dataset>|<path>|<oid>`. |
| `event` | `{uuid, info, scanner: "reposcout", mode, query, observed_at, collected_at}`. |
| `target` | `{url: <blob_or_resolve_url>, domain: "github.com" \| "huggingface.co", ip: null, port: null, asn: null}`. |
| `http` | Tree API request/response metadata (`Authorization: "***"` redacted on GitHub requests; `http.content` holds the file `path`). |
| `attributes` | `url` (`Network activity`), `domain` (`Network activity`), `filename` (`Payload delivery`, containing the relative file path), and `sha256` (`Payload delivery`). |
| `tags` | `["github", "reposcout", "scan"\|"search"]` or `["hf", "reposcout", "scan"\|"search"]`. |
| `raw` | Tree node dictionary (`{path, mode, type, sha, size, url}` for GitHub; `{type, oid, size, path}` for Hugging Face). |

---

## Examples

```sh
# 1. Diff watched GitHub and Hugging Face trees in reposcout.scan.targets
reposcout scan --limit 50 --json

# 2. Search all configured repositories and datasets in scanners/config.yaml
reposcout search --json

# 3. List only .jsonl and .parquet files in a Hugging Face dataset
reposcout search --hf TIGER-Lab/ClawBenchV2Trace --ext .jsonl --ext .parquet --no-save --json

# 4. Inspect a specific GitHub repository and branch
reposcout search --github TIGER-AI-Lab/ClawBench --branch main --limit 25 --json
```

---

## Limitations & Triage

| Issue | Cause | Triage Guidance |
| :--- | :--- | :--- |
| **Tree metadata vs. file content** | `reposcout` enumerates file paths, sizes, and blob SHAs via tree APIs rather than downloading multi-megabyte data files. | Use `target.url` (or `jina scan -u <raw_url>`) to fetch the contents of specific `.jsonl` or `.yaml` files surfaced by `reposcout`. |
| **Synthetic fixture domains** | Benchmark repositories mix real live URLs with mock fixture domains (`api.Promo.com`, `portal.gov.example`, `localhost`). | Cross-check domains extracted from benchmark blobs against Tier 5 placeholder exclusions in `scanners/README.md` before scanning them externally. |

---

## Self-Tests

```sh
reposcout --self-test
uv run scanners/reposcout/scan.py --self-test
uv run scanners/reposcout/search.py --self-test
```
