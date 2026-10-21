#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone Shodan REST API searcher (`shodan/search.py`).

Executes Shodan searches (`/shodan/host/search`, `/shodan/host/count`,
`/shodan/host/{ip}`, and `/dns/domain/{domain}`) using the plain `shodan.queries`
list in `scanners/config.yaml` or direct CLI flags, emitting raw 7-key MISP-shaped
JSONL records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from omegaconf import OmegaConf

SCANNER_NAME = "shodan"
MODE_NAME = "search"
SCANNERS_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCANNERS_DIRECTORY.parent
DEFAULT_CONFIG_PATH = SCANNERS_DIRECTORY / "config.yaml"
RECORD_KEYS = {"id", "event", "target", "http", "attributes", "tags", "raw"}


def load_scanner_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> tuple[dict[str, Any], Path]:
    """Load and merge default settings with the `shodan` scanner section.

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
        cli_args: Parsed command-line arguments.

    Returns:
        Dictionary of HTTP headers.
    """
    headers = {str(k): str(v) for k, v in scanner_config["headers"].items()}
    user_agent = cli_args.user_agent or scanner_config.get("user_agent") or "Shodan-Python/1.31.0"
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
    """Execute an HTTP GET request and return telemetry plus parsed JSON.

    Args:
        request_url: Full URL to fetch.
        request_headers: HTTP headers to attach.
        timeout_seconds: Socket timeout in seconds.

    Returns:
        Telemetry dictionary with `status`, `response_headers`, `content`, and `json`.
    """
    safe_url = re.sub(r"([?&]key=)[^&]+", r"\1***REDACTED***", request_url)
    request = Request(request_url, headers=request_headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:
        raw_bytes = response.read()
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        text_body = raw_bytes.decode("utf-8", errors="replace")
        return {
            "request_url": safe_url,
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
        ("url", "Network activity", target_info.get("url"), True, "Target service URL"),
        ("domain", "Network activity", target_info.get("domain"), True, "Primary hostname"),
        ("ip-dst", "Network activity", target_info.get("ip"), True, "Host IP address"),
        ("port", "Network activity", target_info.get("port"), False, "Service port"),
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
    """Assemble a normalized 7-key MISP-shaped record for `shodan/search.py`.

    Args:
        query_text: Shodan query string, IP, or domain.
        target_info: Normalized target dictionary (`url`, `domain`, `ip`, `port`, `asn`).
        http_exchange: Captured HTTP request/response telemetry.
        tags: List of classification tags.
        raw_payload: Raw upstream data object.
        observed_at: Upstream ISO-8601 observation timestamp.
        identity_key: Deterministic string used to compute the record ID.

    Returns:
        Normalized 7-key MISP-shaped dictionary.
    """
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical_seed = identity_key or (
        f"{SCANNER_NAME}|{MODE_NAME}|{query_text}|{target_info.get('ip') or ''}"
        f"|{target_info.get('port') or ''}|{observed_at or ''}"
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
        output_path: Path to `./data/shodan.jsonl`.

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
    """Append unseen records to `./data/shodan.jsonl`.

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


def convert_banner_to_record(
    banner: dict[str, Any],
    query_text: str,
    http_exchange: dict[str, Any],
) -> dict[str, Any]:
    """Convert a Shodan banner dictionary into a 7-key MISP record.

    Args:
        banner: Shodan host banner dictionary.
        query_text: Query string that returned the banner.
        http_exchange: HTTP telemetry dictionary.

    Returns:
        Normalized 7-key MISP record dictionary.
    """
    ip_address = banner.get("ip_str")
    port_number = banner.get("port")
    hostnames = list(banner.get("hostnames") or [])
    domains = list(banner.get("domains") or [])
    primary_domain = hostnames[0] if hostnames else (domains[0] if domains else None)
    scheme = "https" if ("ssl" in banner or port_number == 443) else "http"
    target_url = f"{scheme}://{ip_address}:{port_number}" if ip_address and port_number else None

    banner_text = str(banner.get("data") or "")
    http_section = dict(banner.get("http") or {})
    observed_at = banner.get("timestamp")
    if isinstance(observed_at, str) and not observed_at.endswith("Z"):
        observed_at = f"{observed_at[:19]}Z"

    target_info = {
        "url": target_url,
        "domain": primary_domain,
        "ip": ip_address,
        "port": port_number,
        "asn": banner.get("asn"),
    }
    banner_exchange = {
        **http_exchange,
        "content": banner_text[:10_000] or http_exchange["content"],
    }
    raw_payload = {
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "asn": banner.get("asn"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "title": http_section.get("title"),
        "server": http_section.get("server"),
        "hostnames": hostnames,
        "domains": domains,
        "cpe": banner.get("cpe") or [],
    }
    return build_misp_record(
        query_text=query_text,
        target_info=target_info,
        http_exchange=banner_exchange,
        tags=["banner"],
        raw_payload=raw_payload,
        observed_at=observed_at,
        identity_key=f"shodan|{ip_address}|{port_number}|{observed_at or ''}",
    )


def execute_query(
    query_text: str,
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Execute a single Shodan search query, count query, IP lookup, or DNS lookup.

    Args:
        query_text: Query string from `shodan.queries` or CLI flags.
        scanner_config: Merged Shodan configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP records.
    """
    api_key = str(scanner_config.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY is required")

    base_url = str(scanner_config["base_url"]).rstrip("/")
    timeout_seconds = float(scanner_config["timeout"])
    limit_count = int(cli_args.limit or scanner_config["limit"])
    request_headers = build_request_headers(scanner_config, cli_args)

    if cli_args.ip:
        target_ip = str(cli_args.ip)
        params: dict[str, Any] = {"key": api_key}
        if cli_args.history:
            params["history"] = "true"
        if cli_args.minify:
            params["minify"] = "true"
        url = f"{base_url}/shodan/host/{quote(target_ip)}?{urlencode(params)}"
        exchange = fetch_fn(url, request_headers, timeout_seconds)
        payload = exchange["json"]
        banners = list(payload.get("data") or [])
        if banners and not cli_args.minify:
            return [
                convert_banner_to_record(banner, f"ip:{target_ip}", exchange)
                for banner in banners[:limit_count]
            ]
        hostnames = list(payload.get("hostnames") or [])
        target_info = {
            "url": f"https://www.shodan.io/host/{target_ip}",
            "domain": hostnames[0] if hostnames else None,
            "ip": target_ip,
            "port": None,
            "asn": payload.get("asn"),
        }
        return [
            build_misp_record(
                query_text=f"ip:{target_ip}",
                target_info=target_info,
                http_exchange=exchange,
                tags=["host"],
                raw_payload=payload,
                observed_at=payload.get("last_update"),
                identity_key=f"shodan|host|{target_ip}|{payload.get('last_update') or ''}",
            )
        ]

    if cli_args.domain:
        domain_name = str(cli_args.domain)
        url = f"{base_url}/dns/domain/{quote(domain_name)}?{urlencode({'key': api_key})}"
        exchange = fetch_fn(url, request_headers, timeout_seconds)
        payload = exchange["json"]
        target_info = {
            "url": f"https://www.shodan.io/domain/{domain_name}",
            "domain": domain_name,
            "ip": None,
            "port": None,
            "asn": None,
        }
        return [
            build_misp_record(
                query_text=f"domain:{domain_name}",
                target_info=target_info,
                http_exchange=exchange,
                tags=["dns"],
                raw_payload=payload,
                identity_key=f"shodan|dns|{domain_name}",
            )
        ]

    effective_query = query_text
    if cli_args.since_days and "after:" not in effective_query:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=float(cli_args.since_days))).strftime(
            "%Y-%m-%d"
        )
        effective_query = f"{effective_query} after:{cutoff}"

    if cli_args.count:
        params = {"key": api_key, "query": effective_query}
        if cli_args.facets:
            params["facets"] = cli_args.facets
        url = f"{base_url}/shodan/host/count?{urlencode(params)}"
        exchange = fetch_fn(url, request_headers, timeout_seconds)
        payload = exchange["json"]
        target_info = {
            "url": f"https://www.shodan.io/search?{urlencode({'query': effective_query})}",
            "domain": None,
            "ip": None,
            "port": None,
            "asn": None,
        }
        return [
            build_misp_record(
                query_text=effective_query,
                target_info=target_info,
                http_exchange=exchange,
                tags=["count"],
                raw_payload=payload,
                identity_key=f"shodan|count|{effective_query}|{payload.get('total')}",
            )
        ]

    params = {"key": api_key, "query": effective_query, "page": int(cli_args.page)}
    if cli_args.facets:
        params["facets"] = cli_args.facets
    url = f"{base_url}/shodan/host/search?{urlencode(params)}"
    exchange = fetch_fn(url, request_headers, timeout_seconds)
    payload = exchange["json"]
    return [
        convert_banner_to_record(banner, effective_query, exchange)
        for banner in list(payload.get("matches") or [])[:limit_count]
    ]


def run_search(
    scanner_config: dict[str, Any],
    cli_args: argparse.Namespace,
    fetch_fn: Any = fetch_json_endpoint,
) -> list[dict[str, Any]]:
    """Run Shodan searches from CLI flags or the `shodan.queries` YAML list.

    Args:
        scanner_config: Merged Shodan configuration dictionary.
        cli_args: Parsed command-line options.
        fetch_fn: Injectable HTTP JSON fetcher.

    Returns:
        List of normalized 7-key MISP records.
    """
    if cli_args.ip or cli_args.domain:
        return execute_query("", scanner_config, cli_args, fetch_fn)

    queries_to_run = list(cli_args.query or scanner_config["queries"])
    delay_seconds = float(scanner_config["delay"])
    records: list[dict[str, Any]] = []
    for index, query_text in enumerate(queries_to_run):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        records.extend(execute_query(str(query_text), scanner_config, cli_args, fetch_fn))
    return records


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for `shodan/search.py`.

    Returns:
        Configured `argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        prog="shodan search",
        description="Search Shodan using config.yaml queries or CLI flags",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to YAML config"
    )
    parser.add_argument("-q", "--query", action="append", help="Shodan search query string")
    parser.add_argument("--ip", help="Specific IPv4/IPv6 host to query (/shodan/host/{ip})")
    parser.add_argument("--domain", help="Domain to query via /dns/domain/{domain}")
    parser.add_argument("--count", action="store_true", help="Use /shodan/host/count endpoint")
    parser.add_argument("--facets", help="Comma-separated Shodan facets (e.g. org,country,port)")
    parser.add_argument("--page", type=int, default=1, help="Search result page (default: 1)")
    parser.add_argument("--limit", type=int, help="Max banners returned per query")
    parser.add_argument("--history", action="store_true", help="Include historical host banners")
    parser.add_argument("--minify", action="store_true", help="Minify /shodan/host/{ip} output")
    parser.add_argument("--since-days", type=float, help="Append after:<YYYY-MM-DD> filter")
    parser.add_argument("--new-only", action="store_true", help="Only print unseen records")
    parser.add_argument("--user-agent", help="Override HTTP User-Agent header")
    parser.add_argument("--header", action="append", default=[], help="Custom header Key:Value")
    parser.add_argument("--output", type=Path, help="Override JSONL output file path")
    parser.add_argument("--no-save", action="store_true", help="Do not persist records to disk")
    parser.add_argument("--json", action="store_true", help="Print JSONL records to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    return parser


def run_self_test() -> int:
    """Run an offline self-test verifying MISP record fields and query dispatch.

    Returns:
        Exit code (`0` on pass).
    """
    scanner_config, _ = load_scanner_config()
    scanner_config["api_key"] = "test-key"
    scanner_config["delay"] = 0.0
    scanner_config["queries"] = ['http.title:"Cairn"']

    def fake_fetch(url: str, headers: dict[str, str], _timeout: float) -> dict[str, Any]:
        body = json.dumps(
            {
                "total": 1,
                "matches": [
                    {
                        "ip_str": "198.51.100.1",
                        "port": 443,
                        "timestamp": "2026-10-19T12:00:00",
                        "hostnames": ["cairn.example.com"],
                        "org": "ExampleISP",
                        "asn": "AS64500",
                        "data": "HTTP/1.1 200 OK\r\n\r\n<title>Cairn</title>",
                        "http": {"title": "Cairn"},
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
    assert records[0]["target"]["ip"] == "198.51.100.1"
    print("[shodan:search] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `shodan/search.py`.

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
        print(f"[shodan:search] total={len(records)} new={len(saved_records)} output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
