# Collectors

A lightweight, configurable public-surface intelligence collection framework. It provides scriptable collectors for monitoring new events, searching existing indexes, and retrieving specific public artifacts, with normalized JSONL output.

---

## Points of Interest

| Domain       | Type   | Operations               |
| :-----:      | :----: | :--------:               |
| jina.ai      | retrieval proxy | download                 |
| urlquery.net | retrieval proxy | scrape, search, download |
| markdown.new | retrieval proxy | ^         |

---

## Envelopes

## Input Envelope

This is the input envelope for the download collector. It is a JSON object with the following fields:

```json
{
    "queries": ["uqscan="],
}
```

## Output Envelope

This is the output envelope for the download collector. It is a JSON object with the following fields:

```json
{
  "record_id": "sha256:…",
  "retrieved_at": "2026-10-21T17:00:00Z",
  "observed_at": "2026-09-29T18:16:37Z",

  "source": "jina",
  "operation": "search",
  "driver": "api",
  "query": "uqscan=",

  "permalink": "https://example.org/trace?uqscan=claude20261019",
  "headers": {
    "content-type": "application/json"
  },
  "http_status": 200,

  "payload": {
    "content": "Full page markdown or response body…",
    "content_type": "text/markdown",
    "content_hash": "sha256:…",
    "raw": {}
  }
}
```




