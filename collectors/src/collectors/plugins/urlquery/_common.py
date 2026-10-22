# plugins/urlquery/_common.py
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from wsgiref import headers
from pathlib import Path

from collectors.registry import build_output_envelope

from omegaconf import OmegaConf


PLUGIN_DIR = Path(__file__).resolve().parent
LOCAL_CONFIG_PATH = PLUGIN_DIR / "config.yaml"


def load_local_context(ctx: dict[str, Any]) -> dict[str, Any]:
    """Fill missing context values from plugins/urlquery/config.yaml."""
    if not LOCAL_CONFIG_PATH.exists():
        return dict(ctx)

    local_cfg = OmegaConf.load(LOCAL_CONFIG_PATH)
    # Support either a plugin-level config or a full surfaces config.
    if "surfaces" in local_cfg:
        local_cfg = local_cfg.get("surfaces", {}).get("urlquery", {})
    elif "urlquery" in local_cfg:
        local_cfg = local_cfg.get("urlquery", {})

    local_dict = OmegaConf.to_container(
        local_cfg, resolve=True
    ) or {}

    # If config has operation-specific values, merge those too.
    scrape_cfg = local_dict.get("scrape", {})
    merged = OmegaConf.merge(
        OmegaConf.create(local_dict),
        OmegaConf.create(scrape_cfg),
        OmegaConf.create(ctx),
    )
    return OmegaConf.to_container(merged, resolve=True)


def require_api_key(ctx: dict[str, Any]) -> str:
    api_key = str(ctx.get("api_key") or ctx.get("env", {}).get("URLQUERY_API_KEY") or "").strip()
    if not api_key:
        raise SystemExit(
            "Error: URLQUERY_API_KEY is required for the 'urlquery' plugin.\n"
            "Fix: Set URLQUERY_API_KEY in your .env file or export it in your shell."
        )
    return api_key


def build_headers(ctx: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in (ctx.get("headers") or {}).items()}
    headers["User-Agent"] = str(ctx.get("user_agent") or "urlquery-python/1.0")
    api_key = require_api_key(ctx)
    # headers["x-apikey"] = api_key
    headers["X-APIKEY"] = api_key
    return headers


def fetch_urlquery_json(url: str, ctx: dict[str, Any]) -> tuple[int, dict[str, str], str, Any]:
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

    text_body = raw_bytes.decode("utf-8", errors="replace")
    parsed_json = None
    if text_body.strip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(text_body)
        except json.JSONDecodeError:
            pass
    return status, resp_headers, text_body, parsed_json


def report_to_envelope(
    report: dict[str, Any],
    query: str,
    status: int,
    resp_headers: dict[str, str],
    ctx: dict[str, Any],
) -> dict[str, Any]:
    report_id = str(report.get("report_id", "unknown"))
    url_obj = report.get("url") or {}
    submitted_url = url_obj.get("addr") or f"https://urlquery.net/report/{report_id}"
    domain = url_obj.get("domain") or (urlparse(submitted_url).hostname if submitted_url else None)
    ip_obj = report.get("ip") or {}

    normalized = {
        "query": query,
        "report_id": report_id,
        "date": report.get("date"),
        "url": submitted_url,
        "domain": domain,
        "ip": ip_obj.get("addr"),
        "asn": ip_obj.get("asn"),
        "stats": report.get("stats"),
        "raw_report": report,
    }

    return build_output_envelope(
        ctx=ctx,
        permalink=submitted_url,
        http_status=status,
        headers=resp_headers,
        content=json.dumps(normalized, ensure_ascii=False),
        content_type="application/json",
    )