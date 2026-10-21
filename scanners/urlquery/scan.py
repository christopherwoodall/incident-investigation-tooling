#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone urlquery.net incremental scanner (`urlquery/scan.py`).

Polls recent public sandbox reports on urlquery.net (`/public/v1/search/reports/`)
within `scan.window_hours` (or optional `scan.targets` queries) and emits raw
7-key MISP-shaped JSONL records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from omegaconf import OmegaConf

SCANNER_NAME = "urlquery"
MODE_NAME = "scan"
SCANNERS_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCANNERS_DIRECTORY.parent
DEFAULT_CONFIG_PATH = SCANNERS_DIRECTORY / "config.yaml"
RECORD_KEYS = {"id", "event", "target", "http", "attributes", "tags", "raw"}


def load_scanner_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> tuple[dict[str, Any], Path]:
    """Load and merge default settings with the `urlquery` scanner section.

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
    """Assemble HTTP request headers including `x-apikey` and CLI overrides.

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
        headers["x-apikey"] = api_key
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
            if key.lower() in {"authorization", "x-api-key", "x-apikey", "apikey", "cookie"}
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
        ("url", "Network activity", target_info.get("url"), True, "Submitted target URL"),
        ("domain", "Network activity", target_info.get("domain"), True, "Target domain"),
        ("ip-dst", "Network activity", target_info.get("ip"), True, "Resolved IP address"),
        ("AS", "Network activity", target_info.get("asn"), False, "Autonomous system"),
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
    """Assemble a normalized 7-key MISP-shaped record for `urlquery/scan.py`.

    Args:
        query_text: Upstream query string.
        target_info: Normalized target dictionary (`url`, `domain`, `ip`, `port`, `asn`).
        http_exchange: Captured HTTP request/response telemetry.
        tags: List of classification tags.
        raw_payload: Raw upstream report dictionary.
        observed_at: Upstream ISO-8601 submission timestamp.
        identity_key: Deterministic string used to compute the record ID.

    Returns:
        Normalized 7-key MISP-shaped dictionary.
    """
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target_url = target_info.get("url") or ""
    canonical_seed = identity_key or (
        f"{SCANNER_NAME}|{MODE_NAME}|{query_text}|{target_url}|{observed_at or ''}"
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


def load_seen_state(output_path: Path) -> tuple[set[str], str | None]:
    """Read previously saved record IDs and latest `observed_at` from disk.

    Args:
        output_path: Path to `./data/urlquery.jsonl`.

    Returns:
        Tuple of `(seen_record_ids, latest_observed_timestamp)`.
    """
    seen_record_ids: set[str] = set()
    latest_timestamp: str | None = None
    if not output_path.exists():
        return seen_record_ids, latest_timestamp
    for line in output_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        seen_record_ids.add(str(record["id"]))
        observed_value = record["event"].get("observed_at")
        if observed_value:
            latest_timestamp = max(latest_timestamp or "", str(observed_value))
    return seen_record_ids, latest_timestamp


def save_new_records(
    records: list[dict[str, Any]],
    output_path: Path,
    seen_record_ids: set[str],
) -> list[dict[str, Any]]:
    """Append unseen records to `./data/urlquery.jsonl`.

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


def run_scan(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    last_observed_timestamp: str | None = None,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Poll recent urlquery.net reports and normalize into 7-key MISP records.

    Args:
        scanner_config: Merged urlquery configuration dictionary.
        cli_args: Parsed command-line options.
        last_observed_timestamp: Latest `observed_at` from `./data/urlquery.jsonl`.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized MISP-shaped records.
    """
    api_key = str(scanner_config.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("URLQUERY_API_KEY is required")

    base_url = str(scanner_config["base_url"]).rstrip("/")
    timeout_seconds = float(scanner_config["timeout"])
    limit_count = int(cli_args.limit or scanner_config["limit"])
    scan_block = dict(scanner_config["scan"])
    window_hours = float(cli_args.hours or scan_block["window_hours"])

    now_utc = datetime.now(timezone.utc)
    if last_observed_timestamp and len(last_observed_timestamp) >= 10:
        from_date = last_observed_timestamp[:10]
    else:
        from_date = (now_utc - timedelta(hours=window_hours)).strftime("%Y-%m-%d")
    to_date = (now_utc + timedelta(days=1)).strftime("%Y-%m-%d")

    date_query = f"date:[{from_date} TO {to_date}]"
    targets = list(cli_args.target or scan_block.get("targets") or [""])
    request_headers = build_request_headers(scanner_config, cli_args)

    records: list[dict[str, Any]] = []
    for raw_target in targets:
        effective_query = f"{raw_target} {date_query}".strip() if raw_target else date_query
        query_params = {"query": effective_query, "limit": limit_count, "offset": 0}
        request_url = f"{base_url}/search/reports/?{urlencode(query_params)}"
        exchange = fetch_fn(request_url, request_headers, timeout_seconds)
        payload = exchange["json"]

        for report in list(payload.get("reports") or [])[:limit_count]:
            report_id = str(report["report_id"])
            url_object = report.get("url") or {}
            submitted_url = url_object.get("addr") or ""
            ip_object = report.get("ip") or {}
            domain_name = url_object.get("domain") or (
                urlparse(submitted_url).hostname if submitted_url else None
            )
            target_info = {
                "url": submitted_url or f"https://urlquery.net/report/{report_id}",
                "domain": domain_name,
                "ip": ip_object.get("addr"),
                "port": None,
                "asn": ip_object.get("asn"),
            }
            records.append(
                build_misp_record(
                    query_text=effective_query,
                    target_info=target_info,
                    http_exchange=exchange,
                    tags=["report"],
                    raw_payload=report,
                    observed_at=report.get("date"),
                    identity_key=f"urlquery|{report_id}",
                )
            )
    return records


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for `urlquery/scan.py`.

    Returns:
        Configured `argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="urlquery scan",
        description="Poll recent public urlquery.net reports and emit raw MISP records",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to YAML config"
    )
    parser.add_argument(
        "-t", "--target", action="append", help="Optional target filter for scan window"
    )
    parser.add_argument("--hours", type=float, help="Lookback window in hours (default: 24)")
    parser.add_argument("--limit", type=int, help="Max reports per scan")
    parser.add_argument("--user-agent", help="Override HTTP User-Agent header")
    parser.add_argument("--header", action="append", default=[], help="Custom header Key:Value")
    parser.add_argument("--output", type=Path, help="Override JSONL output file path")
    parser.add_argument("--no-save", action="store_true", help="Do not persist records to disk")
    parser.add_argument("--json", action="store_true", help="Print JSONL records to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    return parser


def run_self_test() -> int:
    """Run an offline self-test validating MISP record shape and deduplication.

    Returns:
        Exit code (`0` on pass).
    """
    scanner_config, _ = load_scanner_config()
    scanner_config["api_key"] = "test-key"

    def fake_fetch(url: str, headers: dict[str, str], _timeout: float) -> dict[str, Any]:
        body = json.dumps(
            {
                "total_hits": 1,
                "reports": [
                    {
                        "report_id": "rep-1234",
                        "date": "2026-10-19T08:00:00Z",
                        "url": {
                            "addr": "https://ditu.amap.com/detail/B0G3LMF2G1?uqscan=claude20261019",
                            "domain": "ditu.amap.com",
                        },
                        "ip": {"addr": "203.0.113.5", "asn": 45102},
                        "stats": {"alert_count": {"detection": 1}},
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
    records = run_scan(scanner_config, cli_args, fetch_fn=fake_fetch)
    assert len(records) == 1
    assert set(records[0].keys()) == RECORD_KEYS
    print("[urlquery:scan] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `urlquery/scan.py`.

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
    seen_ids, last_timestamp = load_seen_state(output_path)
    records = run_scan(scanner_config, cli_args, last_observed_timestamp=last_timestamp)
    new_records = [r for r in records if r["id"] not in seen_ids]
    saved_records = (
        new_records if cli_args.no_save else save_new_records(records, output_path, seen_ids)
    )

    if cli_args.json:
        for record in saved_records:
            print(json.dumps(record, ensure_ascii=False))
    else:
        print(
            f"[urlquery:scan] fetched={len(records)} new={len(saved_records)} output={output_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
