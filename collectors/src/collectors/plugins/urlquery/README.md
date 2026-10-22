# urlquery.net Collector (`urlquery`)

Queries urlquery.net API endpoints for public sandbox reports, report lookups, and URL reputation verdicts. Requires `URLQUERY_API_KEY` in `.env` or the host environment.

## Supported Operations

- `search`: Query sandbox reports using urlquery query syntax (`url.fqdn:`, `uqscan=`, etc.).
- `download`: Retrieve specific reports by report ID (`rep-...`) or run URL reputation checks.
- `scrape`: One-shot incremental pull of recent public reports within `window_hours` (default `24h`).

## Usage

```bash
# Search public sandbox reports
uv run cli.py urlquery search -q "uqscan="

# Download a specific report by ID
uv run cli.py urlquery download -q "rep-1234"

# Run incremental scrape over the last 24 hours
uv run cli.py urlquery scrape