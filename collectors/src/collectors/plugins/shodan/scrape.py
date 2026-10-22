#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Collect Shodan alert information and recent host-search results.

The CLI owns configuration loading, query resolution, enablement checks, and
JSONL persistence. This module only implements the collector contract.

Run through the project CLI:
    uv run cli.py shodan scrape -q 'http.title:"Cairn"'

Run this file directly:
    uv run --script plugins/shodan/scrape.py -q 'http.title:"Cairn"'
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Ensure imports work both when this file is loaded by the plugin registry and
# when it is executed directly by `uv run --script`.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:  # Support the current package layout and the legacy root-level registry.
    from collectors.registry import build_output_envelope  # type: ignore[attr-defined]  # noqa: E402
except ImportError:  # pragma: no cover - depends on repository layout
    from registry import build_output_envelope  # noqa: E402

SCANNER_NAME = "shodan"
MODE_NAME = "scrape"
DEFAULT_BASE_URL = "https://api.shodan.io"
SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key"}


def _api_key(ctx: dict[str, Any]) -> str:
    """Get the API key from resolved config or the process environment."""
    key = str(ctx.get("api_key") or os.getenv("SHODAN_API_KEY", "")).strip()
    if not key:
        raise SystemExit(
            "Error: SHODAN_API_KEY is missing. Set it in the environment/.env "
            "or configure surfaces.shodan.api_key."
        )
    return key


def _request_json(url: str, ctx: dict[str, Any]) -> tuple[int, dict[str, str], Any]:
    """GET a Shodan JSON endpoint with bounded reads and explicit API errors."""
    timeout = float(ctx.get("timeout", 60.0))
    max_bytes = int(ctx.get("max_response_bytes", 10_000_000))
    user_agent = str(ctx.get("user_agent") or "Shodan-Python/1.31.0")
    headers = {"Accept": "application/json", "User-Agent": user_agent}
    request = Request(url, headers=headers, method="GET")

    try:
        with urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(max_bytes + 1)
    except HTTPError as exc:
        response_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        body = exc.read(max_bytes + 1)
        message = body[:2000].decode("utf-8", errors="replace")
        raise RuntimeError(f"Shodan API returned HTTP {exc.code}: {message}") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach Shodan API: {exc.reason}") from exc

    if len(body) > max_bytes:
        raise RuntimeError(f"Shodan response exceeded max_response_bytes={max_bytes}")

    text = body.decode("utf-8", errors="replace")
    try:
        parsed: Any = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError("Shodan returned a non-JSON response") from exc

    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"Shodan API error: {parsed['error']}")
    return status, response_headers, parsed


def _envelope(
    *,
    ctx: dict[str, Any],
    permalink: str,
    status: int,
    headers: dict[str, str],
    payload: Any,
    query: str = "",
) -> dict[str, Any]:
    """Build the project's standard output envelope for a retrieved item."""
    safe_headers = {
        key: ("[REDACTED]" if key.lower() in SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }
    record = build_output_envelope(
        ctx=ctx,
        permalink=permalink,
        http_status=status,
        headers=safe_headers,
        content=json.dumps(payload, ensure_ascii=False),
        content_type="application/json",
    )
    # Preserve the source query and the unmodified API object for downstream use.
    record["source"] = SCANNER_NAME
    record["operation"] = MODE_NAME
    record["query"] = query
    record["raw"] = payload
    return record


def _banner_permalink(banner: dict[str, Any]) -> str:
    ip = str(banner.get("ip_str") or "").strip()
    if ip:
        return f"https://www.shodan.io/host/{ip}"
    return DEFAULT_BASE_URL


def collect(
    input_envelope: dict[str, list[str]],
    ctx: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Collect alert metadata and Shodan host-search results.

    Input contract remains ``{"queries": ["..."]}``. ``window_hours`` sets
    the default lookback for queries that do not already contain ``after:``.
    """
    api_key = _api_key(ctx)
    base_url = str(ctx.get("base_url") or DEFAULT_BASE_URL).rstrip("/")
    delay = max(0.0, float(ctx.get("delay", 2.0)))
    limit = max(1, int(ctx.get("limit", 50)))
    window_hours = max(0.0, float(ctx.get("window_hours", 168.0)))
    max_alerts = limit
    queries = [str(q).strip() for q in input_envelope.get("queries", []) if str(q).strip()]
    # The CLI requires a non-empty input envelope. `-q alerts` is an explicit
    # sentinel for polling alerts without running a host search.
    alerts_only = bool(queries) and all(q.lower() == "alerts" for q in queries)
    if alerts_only:
        queries = []

    # Use UTC date syntax supported by Shodan's search query language.
    cutoff_date = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d")

    # Poll alert information once. Shodan may return a list or a single object,
    # depending on endpoint/API behavior; normalize both without iterating dict keys.
    alert_url = f"{base_url}/shodan/alert/info?{urlencode({'key': api_key})}"
    status, response_headers, alert_data = _request_json(alert_url, ctx)
    if isinstance(alert_data, list):
        alert_items = alert_data[:max_alerts]
    elif isinstance(alert_data, dict) and isinstance(alert_data.get("alerts"), list):
        alert_items = alert_data["alerts"][:max_alerts]
    elif isinstance(alert_data, dict) and alert_data.get("id"):
        alert_items = [alert_data]
    else:
        alert_items = []

    for alert in alert_items:
        alert_id = str(alert.get("id") or "unknown")
        yield _envelope(
            ctx=ctx,
            permalink=f"{base_url}/shodan/alert/{alert_id}/info",
            status=status,
            headers=response_headers,
            payload=alert,
            query="alerts",
        )

    for index, raw_query in enumerate(queries):
        if delay and (index > 0 or alert_items):
            time.sleep(delay)

        # Respect an explicit after: supplied by the user; otherwise apply the
        # configured lookback. Shodan supports date-based after: filters.
        query = raw_query if "after:" in raw_query.lower() else f"{raw_query} after:{cutoff_date}"
        search_url = f"{base_url}/shodan/host/search?{urlencode({'key': api_key, 'query': query, 'page': 1})}"
        search_status, search_headers, search_data = _request_json(search_url, ctx)
        matches = search_data.get("matches", []) if isinstance(search_data, dict) else []
        if not isinstance(matches, list):
            matches = []

        for banner in matches[:limit]:
            if not isinstance(banner, dict):
                continue
            yield _envelope(
                ctx=ctx,
                permalink=_banner_permalink(banner),
                status=search_status,
                headers=search_headers,
                payload={"query": query, "banner": banner},
                query=query,
            )


def main(argv: list[str] | None = None) -> int:
    """Delegate standalone invocation to the same project CLI dispatcher."""
    from cli import main as cli_main

    args = list(sys.argv[1:] if argv is None else argv)
    return int(cli_main([SCANNER_NAME, MODE_NAME, *args]))


if __name__ == "__main__":
    raise SystemExit(main())
