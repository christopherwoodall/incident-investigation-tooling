import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlencode

from collectors.plugins.urlquery._common import (  # noqa: E402
    load_local_context,
    fetch_urlquery_json,
    report_to_envelope,
    require_api_key,
)


def collect(
    input_envelope: dict[str, list[str]],
    ctx: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Poll URLQuery reports over a configurable date window."""
    ctx = load_local_context(ctx)
    require_api_key(ctx)

    base_url = str(ctx.get("base_url", "https://api.urlquery.net")).rstrip("/")
    delay = float(ctx.get("delay", 2.0))
    limit = int(ctx.get("limit", 50))
    window_hours = float(ctx.get("window_hours", 24.0))

    if window_hours <= 0:
        raise ValueError("window_hours must be greater than zero")

    targets = input_envelope.get("queries") or [""]

    for idx, raw_target in enumerate(targets):
        if idx > 0 and delay > 0:
            time.sleep(delay)

        now_utc = datetime.now(timezone.utc)
        start_date = (now_utc - timedelta(hours=window_hours)).date()
        end_date = now_utc.date()
        date_query = (
            f"date:[{start_date.isoformat()} TO {end_date.isoformat()}]"
        )

        target_str = str(raw_target).strip()
        effective_query = (
            f"({target_str}) AND {date_query}"
            if target_str
            else date_query
        )

        params = {
            "query": effective_query,
            "limit": limit,
            "offset": 0,
        }

        url = f"{base_url}/public/v1/search/reports/?{urlencode(params)}"
        status, headers, _, parsed = fetch_urlquery_json(url, ctx)

        reports = (
            parsed.get("reports", [])
            if isinstance(parsed, dict)
            else []
        )

        for report in list(reports or [])[:limit]:
            yield report_to_envelope(
                report,
                effective_query,
                status,
                headers,
                ctx,
            )
