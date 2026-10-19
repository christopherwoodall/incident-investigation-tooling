#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Self-contained passive YOURLS/shortlink scanner with unified 12-field output."""
from __future__ import annotations

import argparse, gzip, hashlib, json, re, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
from omegaconf import OmegaConf

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"


def match_patterns(text: str, patterns: dict[str, str], keyword: str | None = None) -> dict[str, list[str]]:
    matches = {
        name: hits[:25]
        for name, expr in (patterns or {}).items()
        if (hits := sorted({(m.group(1) if m.lastindex else m.group(0)).strip() for m in re.finditer(expr, text)} - {""}))
    }
    if keyword and keyword.lower() in text.lower():
        matches["keyword"] = [keyword]
    return matches


def make_record(seed: str, query: str, *, url: str | None = None, ip: str | None = None, domain: str | None = None,
                status: int | None = None, matches: dict[str, list[str]] | None = None, tags: list[str] | None = None, raw: Any = None) -> dict[str, Any]:
    key = f"yourls|{seed}|{query}|{url}|{ip}|{json.dumps(raw, sort_keys=True, default=str)[:200]}"
    return {
        "id": f"yourls:{hashlib.sha256(key.encode()).hexdigest()[:12]}",
        "scanner": "yourls", "seed": seed, "query": query,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url, "ip": ip, "domain": domain, "status": status,
        "matches": matches or {}, "tags": list(dict.fromkeys([*(tags or []), *(matches or {}).keys()])), "raw": raw,
    }


def http_get_text(url: str, timeout: int) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = gzip.decompress(raw)
            return int(getattr(resp, "status", 200)), raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), (exc.read().decode("utf-8", errors="replace") if exc.fp else "")


def scan_seed(seed: dict[str, Any], cfg: dict[str, Any], patterns: dict[str, str], args: argparse.Namespace, fetch_fn=http_get_text) -> list[dict[str, Any]]:
    target, timeout, min_bytes = str(seed["query"]).strip(), int(cfg.get("timeout") or 45), int(cfg.get("min_bytes") or 500)
    status, body = fetch_fn(target, timeout)
    if len(body) < min_bytes:
        if retry_delay := float(cfg.get("retry_delay") or 0):
            time.sleep(retry_delay)
        status, body = fetch_fn(target, timeout)

    hits = match_patterns(body, patterns, args.keyword)
    now = datetime.now(timezone.utc)
    cutoff = args.from_date or ((now - timedelta(days=args.since_days)).strftime("%Y-%m-%d") if args.since_days else ((now - timedelta(hours=args.since_hours)).strftime("%Y-%m-%d") if args.since_hours else None))
    dates = hits.get("iso_date") or []
    if (cutoff and dates and max(dates) < cutoff) or (args.to_date and dates and min(dates) > args.to_date):
        return []
    return [make_record(str(seed["name"]), target, url=target, domain=urllib.parse.urlparse(target).hostname, status=status, matches=hits, tags=list(seed.get("tags") or []), raw={"status": status, "bytes": len(body), "html": body})]


def save_records(records: list[dict[str, Any]], data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / "yourls.jsonl"
    with out_path.open("a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return out_path


def run_self_test() -> int:
    cfg = OmegaConf.to_container(OmegaConf.load(DEFAULT_CONFIG), resolve=True)
    assert isinstance(cfg, dict)
    cfg["scanner"]["retry_delay"] = 0
    calls: list[str] = []
    html = '<html><title>7t6-o</title>2026-10-18 <a href="https://webhook.site/12345678-1234-1234-1234-1234567890ab?uqscan=claude20261019">x</a>' + ("p" * 600)
    fake = lambda u, t: (calls.append(u), (200, "tiny") if len(calls) == 1 else (200, html))[1]
    ns = argparse.Namespace(keyword="claude20261019", since_hours=None, since_days=None, from_date="2026-10-01", to_date=None)
    recs = scan_seed(cfg["seeds"][0], cfg["scanner"], cfg["patterns"], ns, fetch_fn=fake)
    assert len(calls) == 2 and len(recs) == 1 and set(recs[0].keys()) == {"id", "scanner", "seed", "query", "observed_at", "url", "ip", "domain", "status", "matches", "tags", "raw"}
    assert recs[0]["matches"]["tag_param"] == ["claude20261019"] and recs[0]["matches"]["webhook_uuid"] == ["12345678-1234-1234-1234-1234567890ab"]
    with tempfile.TemporaryDirectory() as tmp:
        assert save_records(recs, Path(tmp)).is_file()
    print("[yourls] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    for env in (SCRIPT_DIR / ".env", SCRIPT_DIR.parent / ".env", SCRIPT_DIR.parent.parent / ".env"):
        if env.is_file():
            load_dotenv(env, override=False)
    p = argparse.ArgumentParser(description="Passive YOURLS shortlink scanner")
    for flag, kw in [("--config", {"default": str(DEFAULT_CONFIG)}), ("-u", {"dest": "url"}), ("--url", {}), ("-k", {"dest": "keyword"}),
                     ("--keyword", {}), ("--tag", {"action": "append", "default": []}), ("--since-hours", {"type": float}),
                     ("--since-days", {"type": float}), ("--from-date", {}), ("--to-date", {}), ("--max-runtime", {"type": float})]:
        p.add_argument(flag, **kw)
    for flag in ("--filter-seeds", "--json", "--self-test"):
        p.add_argument(flag, action="store_true")
    p.add_argument("--list-seeds", "--dry-run", dest="dry_run", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        return run_self_test()

    cfg = OmegaConf.to_container(OmegaConf.load(args.config), resolve=True)
    assert isinstance(cfg, dict)
    scfg, patterns = cfg.get("scanner") or {}, cfg.get("patterns") or {}
    seeds = [{"name": "adhoc_url", "query": args.url, "tags": ["adhoc"]}] if args.url else [
        s for s in (cfg.get("seeds") or [])
        if (not args.tag or set(args.tag) & set(s.get("tags") or []))
        and (not (args.keyword and args.filter_seeds) or args.keyword.lower() in json.dumps(s).lower())
    ]

    if args.dry_run:
        for s in seeds:
            print(json.dumps(s))
        return 0

    deadline, delay, records = time.monotonic() + float(args.max_runtime or scfg.get("max_runtime") or 300), float(scfg.get("delay") or 3.0), []
    for i, seed in enumerate(seeds):
        if time.monotonic() >= deadline:
            break
        if i > 0 and delay > 0:
            time.sleep(delay)
        records.extend(scan_seed(seed, scfg, patterns, args))

    save_records(records, (Path(args.config).parent / str(scfg.get("data_dir") or "../../data")).resolve())
    for r in records:
        print(json.dumps(r) if args.json else f"[yourls] {r['seed']} ({r['url']}) -> status={r['status']} matches={list(r['matches'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
