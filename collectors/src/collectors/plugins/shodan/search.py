#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
# plugins/shodan/search.py
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode

SCANNERS_ROOT = Path(__file__).resolve().parents[2]
if str(SCANNERS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCANNERS_ROOT))

from plugins.shodan._common import (  # noqa: E402
    banner_to_envelope,
    fetch_shodan_json,
    require_api_key,
)
from registry import build_output_envelope  # noqa: E402


def collect(input_envelope: dict[str, list[str]], ctx: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Run Shodan search queries (`/shodan/host/search` or `count:<query>`)."""
    api_key = require_api_key(ctx)
    base_url = str(ctx.get("base_url", "https://api.shodan.io")).rstrip("/")
    delay = float(ctx.get("delay", 2.0))
    limit = int(ctx.get("limit", 50))
    facets = ctx.get("facets")
    page = int(ctx.get("page", 1))

    for idx, raw_query in enumerate(input_envelope.get("queries", [])):
        if idx > 0 and delay > 0:
            time.sleep(delay)

        query_str = raw_query.strip()
        is_count = query_str.lower().startswith("count:") or bool(ctx.get("count"))
        effective_query = query_str[6:].strip() if query_str.lower().startswith("count:") else query_str

        if is_count:
            params: dict[str, Any] = {"key": api_key, "query": effective_query}
            if facets:
                params["facets"] = str(facets)
            url = f"{base_url}/shodan/host/count?{urlencode(params)}"
            status, headers, text_body, parsed = fetch_shodan_json(url, ctx)
            permalink = f"https://www.shodan.io/search?{urlencode({'query': effective_query})}"
            yield build_output_envelope(
                ctx=ctx,
                permalink=permalink,
                http_status=status,
                headers=headers,
                content=json.dumps(parsed, ensure_ascii=False) if parsed else text_body,
                content_type="application/json",
            )
            continue

        params = {"key": api_key, "query": effective_query, "page": page}
        if facets:
            params["facets"] = str(facets)
        url = f"{base_url}/shodan/host/search?{urlencode(params)}"
        status, headers, text_body, parsed = fetch_shodan_json(url, ctx)

        matches = (parsed or {}).get("matches") if isinstance(parsed, dict) else None
        if matches:
            for banner in list(matches)[:limit]:
                yield banner_to_envelope(banner, effective_query, status, headers, ctx)
        elif status != 200:
            permalink = f"https://www.shodan.io/search?{urlencode({'query': effective_query})}"
            yield build_output_envelope(
                ctx=ctx,
                permalink=permalink,
                http_status=status,
                headers=headers,
                content=text_body,
                content_type="application/json",
            )


if __name__ == "__main__":
    from cli import main
    raise SystemExit(main(["shodan", "search", *sys.argv[1:]]))