import time
from typing import Any, Iterable
from urllib.parse import urlencode


from collectors.plugins.urlquery._common import (
    load_local_context,
    fetch_urlquery_json,
    report_to_envelope,
    require_api_key,
)


def collect(
    input_envelope: dict[str, list[str]],
    ctx: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Search URLQuery reports using one or more queries."""
    ctx = load_local_context(ctx)
    require_api_key(ctx)

    base_url = str(
        ctx.get("base_url", "https://api.urlquery.net")
    ).rstrip("/")
    delay = float(ctx.get("delay", 2.0))
    limit = int(ctx.get("limit", 50))
    offset = int(ctx.get("offset", 0))

    queries = [
        str(query).strip()
        for query in input_envelope.get("queries", [])
        if str(query).strip()
    ]
    if not queries:
        raise ValueError(
            "urlquery search requires at least one query; "
            "pass -q or configure surfaces.urlquery.search.queries"
        )

    start_date = ctx.get("start_date")
    end_date = ctx.get("end_date")

    for idx, query in enumerate(queries):
        if idx > 0 and delay > 0:
            time.sleep(delay)

        params: dict[str, Any] = {
            "query": query,
            "limit": limit,
            "offset": offset,
        }
        if start_date:
            params["start_date"] = str(start_date)
        if end_date:
            params["end_date"] = str(end_date)

        url = (
            f"{base_url}/public/v1/search/reports/"
            f"?{urlencode(params)}"
        )
        status, headers, _, parsed = fetch_urlquery_json(url, ctx)

        reports = (
            parsed.get("reports") or []
            if isinstance(parsed, dict)
            else []
        )

        for report in list(reports)[:limit]:
            yield report_to_envelope(
                report, query, status, headers, ctx
            )
