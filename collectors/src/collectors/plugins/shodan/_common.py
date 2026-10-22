# plugins/shodan/_common.py
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from registry import build_output_envelope


def require_api_key(ctx: dict[str, Any]) -> str:
    api_key = str(ctx.get("api_key") or ctx.get("env", {}).get("SHODAN_API_KEY") or "").strip()
    if not api_key:
        raise SystemExit(
            "Error: SHODAN_API_KEY is required for the 'shodan' plugin.\n"
            "Fix: Set SHODAN_API_KEY in your .env file or export it in your shell."
        )
    return api_key


def build_headers(ctx: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in (ctx.get("headers") or {}).items()}
    headers["User-Agent"] = str(ctx.get("user_agent") or "Shodan-Python/1.31.0")
    return headers


def redact_url_key(url: str) -> str:
    return re.sub(r"([?&]key=)[^&]+", r"\1***REDACTED***", url)


def fetch_shodan_json(url: str, ctx: dict[str, Any]) -> tuple[int, dict[str, str], str, Any]:
    """Execute GET against Shodan API and return (status, headers, raw_text, parsed_json)."""
    timeout = float(ctx.get("timeout", 60.0))
    max_bytes = int(ctx.get("max_response_bytes", 10_000_000))
    req = Request(url, headers=build_headers(ctx), method="GET")

    try:
        with urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read(max_bytes)
            status = int(resp.status)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except HTTPError as exc:
        raw_bytes = exc.read(max_bytes) if exc.fp else b""
        status = int(exc.code)
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}

    resp_headers["x-request-url"] = redact_url_key(url)
    text_body = raw_bytes.decode("utf-8", errors="replace")
    parsed_json = None
    if text_body.strip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(text_body)
        except json.JSONDecodeError:
            pass
    return status, resp_headers, text_body, parsed_json


def banner_to_envelope(
    banner: dict[str, Any],
    query: str,
    status: int,
    resp_headers: dict[str, str],
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """Normalize a single Shodan match/banner into the collector Output Envelope."""
    ip_str = banner.get("ip_str") or "unknown"
    port = banner.get("port")
    http_sec = dict(banner.get("http") or {})
    permalink = (
        f"https://www.shodan.io/host/{ip_str}#{port}"
        if port is not None
        else f"https://www.shodan.io/host/{ip_str}"
    )

    normalized_banner = {
        "query": query,
        "ip": ip_str,
        "port": port,
        "timestamp": banner.get("timestamp"),
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "asn": banner.get("asn"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "title": http_sec.get("title"),
        "server": http_sec.get("server"),
        "hostnames": list(banner.get("hostnames") or []),
        "domains": list(banner.get("domains") or []),
        "cpe": list(banner.get("cpe") or []),
        "vulns": list((banner.get("vulns") or {}).keys()),
        "data": str(banner.get("data") or "")[:20_000],
    }

    return build_output_envelope(
        ctx=ctx,
        permalink=permalink,
        http_status=status,
        headers=resp_headers,
        content=json.dumps(normalized_banner, ensure_ascii=False),
        content_type="application/json",
    )


def is_ip_address(value: str) -> bool:
    cleaned = value.removeprefix("ip:").strip()
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False