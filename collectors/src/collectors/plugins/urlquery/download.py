import sys
import time
from typing import Any, Iterable
from urllib.parse import quote

from collectors.plugins.urlquery._common import (
    load_local_context,
    fetch_urlquery_json,
    report_to_envelope,
    require_api_key,
)
from collectors.registry import build_output_envelope


def collect(
    input_envelope: dict[str, list[str]],
    ctx: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Download specific URLQuery reports by report ID."""
    ctx = load_local_context(ctx)
    require_api_key(ctx)

    base_url = str(ctx.get("base_url", "https://api.urlquery.net")).rstrip("/")
    delay = float(ctx.get("delay", 2.0))
    limit = int(ctx.get("limit", 50))
    targets = input_envelope.get("queries") or []

    for idx, raw_target in enumerate(targets[:limit]):
        report_id = str(raw_target).strip()

        if report_id.startswith("rep:"):
            report_id = report_id.removeprefix("rep:").strip()

        if not report_id:
            continue

        if idx > 0 and delay > 0:
            time.sleep(delay)

        url = (
            f"{base_url}/public/v1/report/"
            f"{quote(report_id, safe='')}"
        )
        status, headers, text_body, parsed = fetch_urlquery_json(url, ctx)

        if status == 200 and isinstance(parsed, dict):
            yield report_to_envelope(
                parsed,
                f"report:{report_id}",
                status,
                headers,
                ctx,
            )
        else:
            yield build_output_envelope(
                ctx=ctx,
                permalink=f"https://urlquery.net/report/{report_id}",
                http_status=status,
                headers=headers,
                content=text_body,
                content_type="application/json",
            )
