#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone crt.sh Certificate Transparency searcher (`crtsh/search.py`).

Queries `https://crt.sh/?q=<pattern>&output=json` using the plain `crtsh.queries`
list in `scanners/config.yaml` or CLI flags, emitting raw 7-key MISP-shaped
JSONL records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from omegaconf import OmegaConf

SCANNER_NAME = "crtsh"
MODE_NAME = "search"
SCANNERS_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCANNERS_DIRECTORY.parent
DEFAULT_CONFIG_PATH = SCANNERS_DIRECTORY / "config.yaml"
RECORD_KEYS = {"id", "event", "target", "http", "attributes", "tags", "raw"}


def load_scanner_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> tuple[dict[str, Any], Path]:
    """Load and merge default settings with the `crtsh` scanner section.

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
    """Assemble HTTP request headers from YAML config and CLI overrides.

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
    """Execute an HTTP GET request to `crt.sh` and parse the JSON response list.

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
            "json": json.loads(text_body) if text_body.strip() else [],
        }


def build_misp_attributes(
    target_info: dict[str, Any],
    http_exchange: dict[str, Any],
    serial_number: str | None = None,
) -> list[dict[str, Any]]:
    """Construct MISP-compatible attribute objects from target and certificate data.

    Args:
        target_info: Dictionary with `url`, `domain`, `ip`, `port`, and `asn`.
        http_exchange: HTTP telemetry dictionary.
        serial_number: Optional X.509 certificate serial number.

    Returns:
        List of MISP attribute dictionaries.
    """
    attributes: list[dict[str, Any]] = []
    attribute_specs = [
        ("url", "Network activity", target_info.get("url"), False, "crt.sh certificate URL"),
        ("domain", "Network activity", target_info.get("domain"), True, "Certificate SAN/CN"),
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
    if serial_number:
        attributes.append(
            {
                "type": "text",
                "category": "Network activity",
                "value": serial_number,
                "to_ids": False,
                "comment": "Certificate serial number",
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
    serial_number: str | None = None,
) -> dict[str, Any]:
    """Assemble a normalized 7-key MISP-shaped record for `crtsh/search.py`.

    Args:
        query_text: crt.sh search pattern.
        target_info: Normalized target dictionary (`url`, `domain`, `ip`, `port`, `asn`).
        http_exchange: Captured HTTP request/response telemetry.
        tags: List of classification tags.
        raw_payload: Raw crt.sh JSON entry.
        observed_at: Upstream ISO-8601 certificate `entry_timestamp` or `not_before`.
        identity_key: Deterministic string used to compute the record ID.
        serial_number: Certificate serial number string.

    Returns:
        Normalized 7-key MISP-shaped dictionary.
    """
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target_domain = target_info.get("domain") or ""
    canonical_seed = identity_key or (
        f"{SCANNER_NAME}|{MODE_NAME}|{query_text}|{target_domain}|{observed_at or ''}"
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
        "attributes": build_misp_attributes(target_info, http_exchange, serial_number),
        "tags": sorted({SCANNER_NAME, MODE_NAME, *tags}),
        "raw": raw_payload,
    }


def load_seen_ids(output_path: Path) -> set[str]:
    """Read previously saved record IDs from disk.

    Args:
        output_path: Path to `./data/crtsh.jsonl`.

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
    """Append unseen records to `./data/crtsh.jsonl`.

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
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Query `crt.sh` for a single SQL wildcard/domain pattern.

    Args:
        query_text: crt.sh query pattern (e.g. `%.hysandbox.tencent-cloud.com`).
        scanner_config: Merged crt.sh configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP-shaped records.
    """
    base_url = str(scanner_config["base_url"]).rstrip("/")
    timeout_seconds = float(scanner_config["timeout"])
    limit_count = int(cli_args.limit or scanner_config["limit"])
    request_headers = build_request_headers(scanner_config, cli_args)

    query_params = {"q": query_text, "output": "json", "exclude": "expired"}
    request_url = f"{base_url}/?{urlencode(query_params)}"
    exchange = fetch_fn(request_url, request_headers, timeout_seconds)
    entries = list(exchange["json"])
    issuer_filter = str(cli_args.issuer or "").lower()

    records: list[dict[str, Any]] = []
    for entry in entries[:limit_count]:
        issuer_name = str(entry.get("issuer_name") or "")
        if issuer_filter and issuer_filter not in issuer_name.lower():
            continue
        cert_id = str(entry.get("id") or "")
        serial_number = str(entry.get("serial_number") or "")
        common_name = str(entry.get("common_name") or "").lstrip("*.")
        name_value = str(entry.get("name_value") or "")
        primary_domain = common_name or (
            name_value.splitlines()[0].lstrip("*.") if name_value else None
        )
        observed_at = str(entry.get("entry_timestamp") or entry.get("not_before") or "")
        if observed_at and not observed_at.endswith("Z"):
            observed_at = f"{observed_at[:19]}Z"

        target_info = {
            "url": f"{base_url}/?id={cert_id}" if cert_id else request_url,
            "domain": primary_domain,
            "ip": None,
            "port": None,
            "asn": None,
        }
        records.append(
            build_misp_record(
                query_text=query_text,
                target_info=target_info,
                http_exchange=exchange,
                tags=["certificate"],
                raw_payload=entry,
                observed_at=observed_at or None,
                identity_key=f"crtsh|{cert_id or serial_number or primary_domain}",
                serial_number=serial_number or None,
            )
        )
    return records


def run_search(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Run crt.sh searches from CLI flags or the `crtsh.queries` YAML list.

    Args:
        scanner_config: Merged crt.sh configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP records.
    """
    queries_to_run: list[str] = []
    if cli_args.query:
        queries_to_run.extend(cli_args.query)
    if cli_args.domain:
        queries_to_run.append(f"%.{str(cli_args.domain).lstrip('%.')}")
    if not queries_to_run:
        queries_to_run = [str(q) for q in scanner_config["queries"]]

    delay_seconds = float(scanner_config["delay"])
    records: list[dict[str, Any]] = []
    for index, query_text in enumerate(queries_to_run):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        records.extend(execute_query(query_text, scanner_config, cli_args, fetch_fn))
    return records


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for `crtsh/search.py`.

    Returns:
        Configured `argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="crtsh search",
        description="Search crt.sh Certificate Transparency logs using config.yaml queries",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to YAML config"
    )
    parser.add_argument("-q", "--query", action="append", help="crt.sh search pattern")
    parser.add_argument("-d", "--domain", help="Domain to search (queries %%.<domain>)")
    parser.add_argument("--issuer", help="Case-insensitive substring required in issuer_name")
    parser.add_argument("--limit", type=int, help="Max certificates per query (default: 100)")
    parser.add_argument("--new-only", action="store_true", help="Only print unseen records")
    parser.add_argument("--user-agent", help="Override HTTP User-Agent header")
    parser.add_argument("--header", action="append", default=[], help="Custom header Key:Value")
    parser.add_argument("--output", type=Path, help="Override JSONL output file path")
    parser.add_argument("--no-save", action="store_true", help="Do not persist records to disk")
    parser.add_argument("--json", action="store_true", help="Print JSONL records to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    return parser


def run_self_test() -> int:
    """Run an offline self-test validating MISP record shape and CT parsing.

    Returns:
        Exit code (`0` on pass).
    """
    scanner_config, _ = load_scanner_config()
    scanner_config["delay"] = 0.0
    scanner_config["queries"] = ["%.hysandbox.tencent-cloud.com"]

    def fake_fetch(url: str, headers: dict[str, str], _timeout: float) -> dict[str, Any]:
        entries = [
            {
                "id": 987654321,
                "issuer_name": "C=CN, O=TrustAsia, CN=TrustAsia TLS RSA CA",
                "common_name": "*.hysandbox.tencent-cloud.com",
                "name_value": "*.hysandbox.tencent-cloud.com\nhysandbox.tencent-cloud.com",
                "entry_timestamp": "2026-10-19T10:15:00",
                "serial_number": "abcdef0123456789",
            }
        ]
        body = json.dumps(entries)
        return {
            "request_url": url,
            "request_headers": headers,
            "status": 200,
            "response_headers": {"content-type": "application/json"},
            "content_type": "application/json",
            "content_length": len(body),
            "content_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "content": body,
            "json": entries,
        }

    cli_args = build_argument_parser().parse_args([])
    records = run_search(scanner_config, cli_args, fetch_fn=fake_fetch)
    assert len(records) == 1
    assert set(records[0].keys()) == RECORD_KEYS
    assert records[0]["target"]["domain"] == "hysandbox.tencent-cloud.com"
    print("[crtsh:search] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `crtsh/search.py`.

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
        print(f"[crtsh:search] total={len(records)} new={len(saved_records)} output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
