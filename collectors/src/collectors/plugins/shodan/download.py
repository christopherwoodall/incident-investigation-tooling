#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
# plugins/shodan/download.py
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlencode

SCANNERS_ROOT = Path(__file__).resolve().parents[2]
if str(SCANNERS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCANNERS_ROOT))

from plugins.shodan._common import (  # noqa: E402
    fetch_shodan_json,
    is_ip_address,
    require_api_key,
)
from registry import build_output_envelope  # noqa: E402


def collect(input_envelope: dict[str, list[str]], ctx: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Download specific IP host records, domain DNS records, or alert info from Shodan."""
    api_key = require_api_key(ctx)
    base_url = str(ctx.get("base_url", "https://api.shodan.io")).rstrip("/")
    delay = float(ctx.get("delay", 2.0))
    limit = int(ctx.get("limit", 50))

    for idx, target in enumerate(input_envelope.get("queries", [])[:limit]):
        if idx > 0 and delay > 0:
            time.sleep(delay)

        item = target.strip()

        # 1. Alerts inventory ("alerts" or "alert:info")
        if item.lower() in {"alerts", "alert:info"}:
            url = f"{base_url}/shodan/alert/info?{urlencode({'key': api_key})}"
            status, headers, text_body, parsed = fetch_shodan_json(url, ctx)
            yield build_output_envelope(
                ctx=ctx,
                permalink="https://monitor.shodan.io/alerts",
                http_status=status,
                headers=headers,
                content=json.dumps(parsed, ensure_ascii=False) if parsed is not None else text_body,
                content_type="application/json",
            )

        # 2. Specific IPv4 / IPv6 host lookup (/shodan/host/{ip})
        elif is_ip_address(item):
            ip_addr = item.removeprefix("ip:").strip()
            params: dict[str, str] = {"key": api_key}
            if ctx.get("history"):
                params["history"] = "true"
            if ctx.get("minify"):
                params["minify"] = "true"
            url = f"{base_url}/shodan/host/{quote(ip_addr)}?{urlencode(params)}"
            status, headers, text_body, parsed = fetch_shodan_json(url, ctx)
            yield build_output_envelope(
                ctx=ctx,
                permalink=f"https://www.shodan.io/host/{ip_addr}",
                http_status=status,
                headers=headers,
                content=json.dumps(parsed, ensure_ascii=False) if parsed is not None else text_body,
                content_type="application/json",
            )

        # 3. Domain DNS lookup (/dns/domain/{domain})
        else:
            domain = item.removeprefix("domain:").strip()
            url = f"{base_url}/dns/domain/{quote(domain)}?{urlencode({'key': api_key})}"
            status, headers, text_body, parsed = fetch_shodan_json(url, ctx)
            yield build_output_envelope(
                ctx=ctx,
                permalink=f"https://www.shodan.io/domain/{domain}",
                http_status=status,
                headers=headers,
                content=json.dumps(parsed, ensure_ascii=False) if parsed is not None else text_body,
                content_type="application/json",
            )


if __name__ == "__main__":
    from cli import main
    raise SystemExit(main(["shodan", "download", *sys.argv[1:]]))