#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone Jina AI web searcher (`jina/search.py`).

Queries the Jina Search API (`https://s.jina.ai/<query>`) using the plain
`jina.queries` list in `scanners/config.yaml` or `-q/--query` on the CLI,
emitting raw 7-key MISP-shaped JSONL records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from omegaconf import OmegaConf

SCANNER_NAME = "jina"
MODE_NAME = "search"
SCANNERS_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCANNERS_DIRECTORY.parent
DEFAULT_CONFIG_PATH = SCANNERS_DIRECTORY / "config.yaml"
RECORD_KEYS = {"id", "event", "target", "http", "attributes", "tags", "raw"}


def load_scanner_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> tuple[dict[str, Any], Path]:
    """Load and merge default settings with the `jina` scanner section.

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
) -> dict[str, str]:
    """Assemble Jina Search (`s.jina.ai`) HTTP headers and optional Bearer token.

    Args:
        scanner_config: Merged scanner configuration dictionary.
        cli_args: Parsed command-line options.

    Returns:
        Dictionary of HTTP request headers.
    """
    headers = {str(k): str(v) for k, v in scanner_config["headers"].items()}
    user_agent = cli_args.user_agent or scanner_config.get("user_agent")
    if user_agent:
        headers["User-Agent"] = str(user_agent)
    api_key = str(scanner_config.get("api_key") or "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if cli_args.site:
        headers["X-Site"] = str(cli_args.site)
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


def fetch_search_endpoint(
    request_url: str,
    request_headers: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Execute a Jina Search (`s.jina.ai`) HTTP GET request and parse JSON/text.

    Args:
        request_url: Full `s.jina.ai` URL to fetch.
        request_headers: HTTP headers to attach.
        timeout_seconds: Socket timeout in seconds.

    Returns:
        Telemetry dictionary with `status`, `response_headers`, `content`, and `json`.
    """
    request = Request(request_url, headers=request_headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:
        raw_bytes = response.read(250_000)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        text_body = raw_bytes.decode("utf-8", errors="replace")
        parsed_json = json.loads(text_body) if text_body.strip().startswith("{") else {}
        return {
            "request_url": request_url,
            "request_headers": redact_sensitive_headers(request_headers),
            "status": int(response.status),
            "response_headers": response_headers,
            "content_type": response_headers.get("content-type", "application/json"),
            "content_length": len(raw_bytes),
            "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "content": text_body[:20_000],
            "json": parsed_json,
        }


def build_misp_attributes(
    target_info: dict[str, Any],
    http_exchange: dict[str, Any],
) -> list[dict[str, Any]]:
    """Construct MISP-compatible attribute objects from target and HTTP data.

    Args:
        target_info: Dictionary with `url`, `domain`, `ip`, `port`, and `asn`.
        http_exchange: HTTP telemetry dictionary.

    Returns:
        List of MISP attribute dictionaries.
    """
    attributes: list[dict[str, Any]] = []
    attribute_specs = [
        ("url", "Network activity", target_info.get("url"), True, "Search result URL"),
        ("domain", "Network activity", target_info.get("domain"), True, "Search result domain"),
        (
            "sha256",
            "Payload delivery",
            http_exchange.get("content_sha256"),
            False,
            "SHA-256 of HTTP response body",
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
) -> dict[str, Any]:
    """Assemble a normalized 7-key MISP-shaped record for `jina/search.py`.

    Args:
        query_text: Web search query executed on `s.jina.ai`.
        target_info: Normalized target dictionary (`url`, `domain`, `ip`, `port`, `asn`).
        http_exchange: Captured HTTP request/response telemetry.
        tags: List of classification tags.
        raw_payload: Raw Jina search result item.
        observed_at: Upstream ISO-8601 timestamp if available.
        identity_key: Deterministic string used to compute the record ID.

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
        "attributes": build_misp_attributes(target_info, http_exchange),
        "tags": sorted({SCANNER_NAME, MODE_NAME, *tags}),
        "raw": raw_payload,
    }


def load_seen_ids(output_path: Path) -> set[str]:
    """Read previously saved record IDs from disk.

    Args:
        output_path: Path to `./data/jina.jsonl`.

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
    """Append unseen records to `./data/jina.jsonl`.

    Args:
        records: Candidate records produced by the search.
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


def execute_query(
    query_text: str,
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_search_endpoint,
) -> list[dict[str, Any]]:
    """Execute a single `s.jina.ai` web search query and emit MISP records.

    Args:
        query_text: Search query string.
        scanner_config: Merged Jina configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP fetcher.

    Returns:
        List of normalized 7-key MISP-shaped records.
    """
    base_url = str(scanner_config["base_url"]).rstrip("/")
    timeout_seconds = float(scanner_config["timeout"])
    limit_count = int(cli_args.limit or scanner_config["limit"])
    request_headers = build_request_headers(scanner_config, cli_args)

    search_url = f"{base_url}/{quote(query_text)}"
    exchange = fetch_fn(search_url, request_headers, timeout_seconds)
    payload = exchange["json"]
    data_items = list(payload.get("data") or [])

    if data_items:
        records: list[dict[str, Any]] = []
        for item in data_items[:limit_count]:
            result_url = str(item.get("url") or search_url)
            item_content = str(item.get("content") or item.get("description") or "")
            target_info = {
                "url": result_url,
                "domain": urlparse(result_url).hostname,
                "ip": None,
                "port": None,
                "asn": None,
            }
            item_exchange = {**exchange, "content": item_content[:20_000]}
            records.append(
                build_misp_record(
                    query_text=query_text,
                    target_info=target_info,
                    http_exchange=item_exchange,
                    tags=["s_jina"],
                    raw_payload=item,
                    observed_at=item.get("publishedTime"),
                    identity_key=f"jina|search|{query_text}|{result_url}",
                )
            )
        return records

    target_info = {
        "url": search_url,
        "domain": cli_args.site or "s.jina.ai",
        "ip": None,
        "port": None,
        "asn": None,
    }
    return [
        build_misp_record(
            query_text=query_text,
            target_info=target_info,
            http_exchange=exchange,
            tags=["s_jina"],
            raw_payload=payload or {"search_url": search_url},
            identity_key=f"jina|search|{query_text}|{exchange['content_sha256']}",
        )
    ]


def run_search(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_search_endpoint,
) -> list[dict[str, Any]]:
    """Run Jina web searches from CLI flags or the `jina.queries` YAML list.

    Args:
        scanner_config: Merged Jina configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP fetcher.

    Returns:
        List of normalized 7-key MISP-shaped records.
    """
    queries_to_run = list(cli_args.query or scanner_config["queries"])
    delay_seconds = float(scanner_config["delay"])
    records: list[dict[str, Any]] = []
    for index, query_text in enumerate(queries_to_run):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        records.extend(execute_query(str(query_text), scanner_config, cli_args, fetch_fn))
    return records


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for `jina/search.py`.

    Returns:
        Configured `argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="jina search",
        description="Search the web via s.jina.ai using config.yaml queries or -q <query>",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to YAML config"
    )
    parser.add_argument("-q", "--query", action="append", help="Web search query for s.jina.ai")
    parser.add_argument("--site", help="Restrict s.jina.ai search to a domain (X-Site header)")
    parser.add_argument("--limit", type=int, help="Max search results per query")
    parser.add_argument("--new-only", action="store_true", help="Only print unseen records")
    parser.add_argument("--user-agent", help="Override HTTP User-Agent header")
    parser.add_argument("--header", action="append", default=[], help="Custom header Key:Value")
    parser.add_argument("--output", type=Path, help="Override JSONL output file path")
    parser.add_argument("--no-save", action="store_true", help="Do not persist records to disk")
    parser.add_argument("--json", action="store_true", help="Print JSONL records to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    return parser


def run_self_test() -> int:
    """Run an offline self-test validating `s.jina.ai` response parsing and MISP shape.

    Returns:
        Exit code (`0` on pass).
    """
    scanner_config, _ = load_scanner_config()
    scanner_config["delay"] = 0.0
    scanner_config["queries"] = ["uqscan webhook.site"]

    def fake_fetch(url: str, headers: dict[str, str], _timeout: float) -> dict[str, Any]:
        body = json.dumps(
            {
                "code": 200,
                "status": 20000,
                "data": [
                    {
                        "title": "Trace Result",
                        "url": "https://example.org/trace?uqscan=claude20261019",
                        "description": "Webhook callback trace",
                        "content": "Full page markdown content",
                    }
                ],
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
    records = run_search(scanner_config, cli_args, fetch_fn=fake_fetch)
    assert len(records) == 1
    assert set(records[0].keys()) == RECORD_KEYS
    assert records[0]["target"]["domain"] == "example.org"
    print("[jina:search] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `jina/search.py`.

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
    records = run_search(scanner_config, cli_args)
    new_records = [r for r in records if r["id"] not in seen_ids]
    saved_records = (
        new_records if cli_args.no_save else save_new_records(records, output_path, seen_ids)
    )
    records_to_print = saved_records if cli_args.new_only else records

    if cli_args.json:
        for record in records_to_print:
            print(json.dumps(record, ensure_ascii=False))
    else:
        print(f"[jina:search] total={len(records)} new={len(saved_records)} output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
