# Shodan Collector (`shodan`)

Queries the Shodan REST API (`https://api.shodan.io`) for host banners, facet counts, specific IP profiles, domain DNS records, and network alerts. Requires `SHODAN_API_KEY` in `.env` or the host environment.

## Supported Operations

- `search`: Run Shodan search dorks via `/shodan/host/search` (or prefix a query with `count:` to hit `/shodan/host/count`).
- `download`: Retrieve specific artifacts by IP (`/shodan/host/{ip}`), domain (`/dns/domain/{domain}`), or `"alerts"` (`/shodan/alert/info`).
- `scrape`: Incremental monitor that polls `/shodan/alert/info` and runs queries with an automatic `after:<YYYY-MM-DD>` cutoff (`window_hours`, default `168`).

## Usage

```bash
# Search Shodan dorks
uv run cli.py shodan search -q 'http.title:"Cairn"'

# Count matching hosts with facets
uv run cli.py shodan search -q 'count:http.title:"Cairn"' -D surfaces.shodan.search.facets="org,country,port"

# Download a specific IP host profile or domain DNS record
uv run cli.py shodan download -q "198.51.100.1" -q "example.org"

# Run incremental lookback scrape (alerts + queries with after:<date>)
uv run cli.py shodan scrape -q 'http.title:"Cairn"'