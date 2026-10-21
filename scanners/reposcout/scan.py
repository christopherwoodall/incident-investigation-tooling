#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone RepoScout incremental manifest scanner (`reposcout/scan.py`).

Walks watched GitHub repositories (`github:owner/repo`) and HuggingFace datasets
(`hf:org/dataset`) configured in `reposcout.scan.targets` in `scanners/config.yaml`
and emits raw 7-key MISP-shaped records for candidate data files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from omegaconf import OmegaConf

SCANNER_NAME = "reposcout"
MODE_NAME = "scan"
HUGGINGFACE_API_BASE = "https://huggingface.co/api"
CANDIDATE_EXTENSIONS = (".json", ".jsonl", ".ndjson", ".parquet", ".arrow", ".csv", ".tsv")
SCANNERS_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCANNERS_DIRECTORY.parent
DEFAULT_CONFIG_PATH = SCANNERS_DIRECTORY / "config.yaml"
RECORD_KEYS = {"id", "event", "target", "http", "attributes", "tags", "raw"}


def load_scanner_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> tuple[dict[str, Any], Path]:
    """Load and merge default settings with the `reposcout` scanner section.

    Args:
        config_path: Path to `scanners/config.yaml`.

    Returns:
        Tuple of `(scanner_config, output_file_path)`.
    """
    load_dotenv(REPOSITORY_ROOT / ".env")
    load_dotenv(SCANNERS_DIRECTORY / ".env")
    raw_config = OmegaConf.load(config_path)
    resolved_tree = OmegaConf.to_container(raw_config, resolve=True)
    assert isinstance(resolved_tree, dict)

    defaults = dict(resolved_tree["defaults"])
    section = dict(resolved_tree[SCANNER_NAME])
    merged_headers = {
        **dict(defaults.get("headers") or {}),
        **dict(section.get("headers") or {}),
    }
    scanner_config = {**defaults, **section, "headers": merged_headers}

    data_dir = (config_path.parent / str(resolved_tree["data_dir"])).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    return scanner_config, data_dir / f"{SCANNER_NAME}.jsonl"


def build_request_headers(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    include_github_auth: bool = False,
) -> dict[str, str]:
    """Assemble HTTP request headers with optional GitHub Bearer token.

    Args:
        scanner_config: Merged scanner configuration dictionary.
        cli_args: Parsed command-line options.
        include_github_auth: Whether to attach `Authorization: Bearer <GITHUB_TOKEN>`.

    Returns:
        Dictionary of HTTP request headers.
    """
    headers = {str(k): str(v) for k, v in scanner_config["headers"].items()}
    user_agent = cli_args.user_agent or scanner_config.get("user_agent")
    if user_agent:
        headers["User-Agent"] = str(user_agent)
    api_key = str(scanner_config.get("api_key") or "").strip()
    if include_github_auth and api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    for header_entry in cli_args.header:
        key, value = header_entry.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def redact_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask authentication headers before persisting telemetry.

    Args:
        headers: Outgoing HTTP request headers.

    Returns:
        Copy of headers with secret values replaced by `***REDACTED***`.
    """
    return {
        key: (
            "***REDACTED***"
            if key.lower() in {"authorization", "x-api-key", "apikey", "cookie"}
            else value
        )
        for key, value in headers.items()
    }


def fetch_json_endpoint(
    request_url: str,
    request_headers: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Execute an HTTP GET request and return telemetry plus parsed JSON.

    Args:
        request_url: Full URL to fetch.
        request_headers: HTTP headers to attach.
        timeout_seconds: Socket timeout in seconds.

    Returns:
        Telemetry dictionary with `status`, `response_headers`, `content`, and `json`.
    """
    request = Request(request_url, headers=request_headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:
        raw_bytes = response.read()
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        text_body = raw_bytes.decode("utf-8", errors="replace")
        return {
            "request_url": request_url,
            "request_headers": redact_sensitive_headers(request_headers),
            "status": int(response.status),
            "response_headers": response_headers,
            "content_type": response_headers.get("content-type", "application/json"),
            "content_length": len(raw_bytes),
            "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "content": text_body[:20_000],
            "json": json.loads(text_body) if text_body.strip() else {},
        }


def build_misp_attributes(
    target_info: dict[str, Any],
    http_exchange: dict[str, Any],
    file_path: str | None = None,
) -> list[dict[str, Any]]:
    """Construct MISP-compatible attribute objects from target and file data.

    Args:
        target_info: Dictionary with `url`, `domain`, `ip`, `port`, and `asn`.
        http_exchange: HTTP telemetry dictionary.
        file_path: Repository-relative path of the candidate file.

    Returns:
        List of MISP attribute dictionaries.
    """
    attributes: list[dict[str, Any]] = []
    attribute_specs = [
        ("url", "Network activity", target_info.get("url"), False, "Candidate file URL"),
        ("domain", "Network activity", target_info.get("domain"), False, "Repository host"),
        ("filename", "Payload delivery", file_path, False, "Repository file path"),
        (
            "sha256",
            "Payload delivery",
            http_exchange.get("content_sha256"),
            False,
            "SHA-256 of tree API response",
        ),
    ]
    for attr_type, category, value, to_ids, comment in attribute_specs:
        if value is not None and value != "":
            attributes.append(
                {
                    "type": attr_type,
                    "category": category,
                    "value": str(value),
                    "to_ids": to_ids,
                    "comment": comment,
                }
            )
    return attributes


def build_misp_record(
    *,
    query_text: str,
    target_info: dict[str, Any],
    http_exchange: dict[str, Any],
    tags: list[str],
    raw_payload: dict[str, Any],
    observed_at: str | None = None,
    identity_key: str | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Assemble a normalized 7-key MISP-shaped record for `reposcout/scan.py`.

    Args:
        query_text: Repository identifier (`github:owner/repo` or `hf:org/dataset`).
        target_info: Normalized target dictionary (`url`, `domain`, `ip`, `port`, `asn`).
        http_exchange: Captured HTTP request/response telemetry.
        tags: List of classification tags.
        raw_payload: Raw tree entry dictionary.
        observed_at: Upstream ISO-8601 timestamp if available.
        identity_key: Deterministic string used to compute the record ID.
        file_path: Repository-relative file path.

    Returns:
        Normalized 7-key MISP-shaped dictionary.
    """
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical_seed = identity_key or (
        f"{SCANNER_NAME}|{MODE_NAME}|{query_text}|{target_info.get('url') or ''}"
    )
    digest = hashlib.sha256(canonical_seed.encode("utf-8")).hexdigest()
    record_id = f"{SCANNER_NAME}:{digest[:12]}"
    event_uuid = f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"

    return {
        "id": record_id,
        "event": {
            "uuid": event_uuid,
            "info": f"{SCANNER_NAME} {MODE_NAME}: {query_text}",
            "scanner": SCANNER_NAME,
            "mode": MODE_NAME,
            "query": query_text,
            "observed_at": observed_at or collected_at,
            "collected_at": collected_at,
        },
        "target": {
            "url": target_info.get("url"),
            "domain": target_info.get("domain"),
            "ip": target_info.get("ip"),
            "port": target_info.get("port"),
            "asn": target_info.get("asn"),
        },
        "http": {
            "method": "GET",
            "request_url": http_exchange["request_url"],
            "request_headers": http_exchange["request_headers"],
            "status": int(http_exchange["status"]),
            "response_headers": http_exchange["response_headers"],
            "content_type": http_exchange["content_type"],
            "content_length": int(http_exchange["content_length"]),
            "content_sha256": http_exchange["content_sha256"],
            "content": http_exchange["content"],
        },
        "attributes": build_misp_attributes(target_info, http_exchange, file_path),
        "tags": sorted({SCANNER_NAME, MODE_NAME, *tags}),
        "raw": raw_payload,
    }


def load_seen_ids(output_path: Path) -> set[str]:
    """Read previously saved record IDs from disk.

    Args:
        output_path: Path to `./data/reposcout.jsonl`.

    Returns:
        Set of persisted record IDs.
    """
    if not output_path.exists():
        return set()
    return {
        str(json.loads(line)["id"])
        for line in output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def save_new_records(
    records: list[dict[str, Any]],
    output_path: Path,
    seen_record_ids: set[str],
) -> list[dict[str, Any]]:
    """Append unseen records to `./data/reposcout.jsonl`.

    Args:
        records: Candidate records produced by the scan.
        output_path: Destination JSONL path.
        seen_record_ids: Set of already-persisted record IDs.

    Returns:
        List of newly persisted records.
    """
    newly_saved: list[dict[str, Any]] = []
    for record in records:
        record_id = str(record["id"])
        if record_id not in seen_record_ids:
            seen_record_ids.add(record_id)
            newly_saved.append(record)
    if newly_saved:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as file_handle:
            for record in newly_saved:
                file_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return newly_saved


def parse_repo_target(target_spec: str) -> tuple[str, str]:
    """Split a target string (`github:owner/repo` or `hf:org/dataset`) into `(source, slug)`.

    Args:
        target_spec: Target specification string from `config.yaml` or CLI.

    Returns:
        Tuple of `("github" | "hf", "owner/repo")`.
    """
    if target_spec.startswith("hf:") or target_spec.startswith("huggingface:"):
        return "hf", target_spec.split(":", 1)[1].strip()
    if target_spec.startswith("github:"):
        return "github", target_spec.split(":", 1)[1].strip()
    return "github", target_spec.strip()


def inspect_target(
    target_spec: str,
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Fetch recursive file tree for a GitHub repo or HuggingFace dataset.

    Args:
        target_spec: Target specification (`github:owner/repo` or `hf:org/dataset`).
        scanner_config: Merged RepoScout configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP-shaped records.
    """
    source_type, repo_slug = parse_repo_target(target_spec)
    github_base = str(scanner_config["base_url"]).rstrip("/")
    timeout_seconds = float(scanner_config["timeout"])
    limit_count = int(cli_args.limit or scanner_config["limit"])

    if source_type == "hf":
        headers = build_request_headers(scanner_config, cli_args, include_github_auth=False)
        tree_url = (
            f"{HUGGINGFACE_API_BASE}/datasets/{quote(repo_slug, safe='/')}/tree/main?recursive=true"
        )
        exchange = fetch_fn(tree_url, headers, timeout_seconds)
        items = list(exchange["json"])
        entries = [
            {
                "path": item["path"],
                "size": item.get("size"),
                "sha": item.get("oid"),
                "url": f"https://huggingface.co/datasets/{repo_slug}/blob/main/{item['path']}",
                "domain": "huggingface.co",
            }
            for item in items
            if item.get("type") == "file"
        ]
    else:
        headers = build_request_headers(scanner_config, cli_args, include_github_auth=True)
        tree_url = f"{github_base}/repos/{quote(repo_slug, safe='/')}/git/trees/main?recursive=1"
        exchange = fetch_fn(tree_url, headers, timeout_seconds)
        tree_list = list(exchange["json"].get("tree") or [])
        entries = [
            {
                "path": item["path"],
                "size": item.get("size"),
                "sha": item.get("sha"),
                "url": f"https://github.com/{repo_slug}/blob/main/{item['path']}",
                "domain": "github.com",
            }
            for item in tree_list
            if item.get("type") == "blob"
        ]

    records: list[dict[str, Any]] = []
    for entry in entries:
        path_str = str(entry["path"])
        if not path_str.lower().endswith(CANDIDATE_EXTENSIONS):
            continue
        target_info = {
            "url": entry["url"],
            "domain": entry["domain"],
            "ip": None,
            "port": None,
            "asn": None,
        }
        records.append(
            build_misp_record(
                query_text=target_spec,
                target_info=target_info,
                http_exchange={**exchange, "content": path_str},
                tags=[source_type],
                raw_payload=entry,
                identity_key=f"reposcout|{repo_slug}|{path_str}|{entry.get('sha') or ''}",
                file_path=path_str,
            )
        )
        if len(records) >= limit_count:
            break
    return records


def run_scan(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Run incremental tree diff scan across `reposcout.scan.targets`.

    Args:
        scanner_config: Merged RepoScout configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP records.
    """
    scan_block = dict(scanner_config["scan"])
    targets = list(cli_args.target or scan_block["targets"])
    delay_seconds = float(scanner_config["delay"])
    records: list[dict[str, Any]] = []
    for index, target_spec in enumerate(targets):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        records.extend(inspect_target(str(target_spec), scanner_config, cli_args, fetch_fn))
    return records


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for `reposcout/scan.py`.

    Returns:
        Configured `argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="reposcout scan",
        description="Diff watched GitHub/HuggingFace trees and emit raw MISP records",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to YAML config"
    )
    parser.add_argument(
        "-t", "--target", action="append", help="Override target (github:owner/repo or hf:org/ds)"
    )
    parser.add_argument("--limit", type=int, help="Max candidate files per repository")
    parser.add_argument("--user-agent", help="Override HTTP User-Agent header")
    parser.add_argument("--header", action="append", default=[], help="Custom header Key:Value")
    parser.add_argument("--output", type=Path, help="Override JSONL output file path")
    parser.add_argument("--no-save", action="store_true", help="Do not persist records to disk")
    parser.add_argument("--json", action="store_true", help="Print JSONL records to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    return parser


def run_self_test() -> int:
    """Run an offline self-test validating MISP record shape and tree parsing.

    Returns:
        Exit code (`0` on pass).
    """
    scanner_config, _ = load_scanner_config()
    scanner_config["delay"] = 0.0
    scanner_config["scan"] = {"window_hours": 24, "targets": ["github:TIGER-AI-Lab/ClawBench"]}

    def fake_fetch(url: str, headers: dict[str, str], _timeout: float) -> dict[str, Any]:
        body = json.dumps(
            {
                "tree": [
                    {"path": "README.md", "type": "blob", "size": 100, "sha": "aaa"},
                    {
                        "path": "data/trajectories.jsonl",
                        "type": "blob",
                        "size": 4096,
                        "sha": "bbb123",
                    },
                ]
            }
        )
        return {
            "request_url": url,
            "request_headers": headers,
            "status": 200,
            "response_headers": {"content-type": "application/json"},
            "content_type": "application/json",
            "content_length": len(body),
            "content_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "content": body,
            "json": json.loads(body),
        }

    cli_args = build_argument_parser().parse_args([])
    records = run_scan(scanner_config, cli_args, fetch_fn=fake_fetch)
    assert len(records) == 1
    assert set(records[0].keys()) == RECORD_KEYS
    print("[reposcout:scan] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `reposcout/scan.py`.

    Args:
        argv: Optional argument list override.

    Returns:
        Exit code (`0` on success).
    """
    parser = build_argument_parser()
    cli_args = parser.parse_args(argv)
    if cli_args.self_test:
        return run_self_test()

    scanner_config, default_output = load_scanner_config(cli_args.config)
    output_path = cli_args.output or default_output
    seen_ids = load_seen_ids(output_path)
    records = run_scan(scanner_config, cli_args)
    new_records = [r for r in records if r["id"] not in seen_ids]
    saved_records = (
        new_records if cli_args.no_save else save_new_records(records, output_path, seen_ids)
    )

    if cli_args.json:
        for record in saved_records:
            print(json.dumps(record, ensure_ascii=False))
    else:
        print(
            f"[reposcout:scan] fetched={len(records)} new={len(saved_records)} output={output_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
