#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Self-contained Shodan scanner (count, search, host) with unified 12-field output."""
from __future__ import annotations

import argparse, hashlib, json, os, re, sys, tempfile, time, urllib.parse, urllib.request
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
    key = f"shodan|{seed}|{query}|{url}|{ip}|{json.dumps(raw, sort_keys=True, default=str)[:200]}"
    return {
        "id": f"shodan:{hashlib.sha256(key.encode()).hexdigest()[:12]}",
        "scanner": "shodan", "seed": seed, "query": query,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url, "ip": ip, "domain": domain, "status": status,
        "matches": matches or {}, "tags": list(dict.fromkeys([*(tags or []), *(matches or {}).keys()])), "raw": raw,
    }


def timebox_query(q: str, since_hours: float | None, since_days: float | None, from_date: str | None, to_date: str | None) -> str:
    now = datetime.now(timezone.utc)
    start = from_date or ((now - timedelta(days=since_days)).strftime("%Y-%m-%d") if since_days else ((now - timedelta(hours=since_hours)).strftime("%Y-%m-%d") if since_hours else None))
    q = f"{q} after:{start}" if start and "after:" not in q else q
    return f"{q} before:{to_date}".strip() if to_date and "before:" not in q else q.strip()


def http_get_json(url: str, timeout: int) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "incident-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def scan_seed(seed: dict[str, Any], cfg: dict[str, Any], patterns: dict[str, str], args: argparse.Namespace, fetch_fn=http_get_json) -> list[dict[str, Any]]:
    key = str(cfg.get("api_key") or os.environ.get("SHODAN_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("Missing SHODAN_API_KEY")
    base, timeout = str(cfg.get("base_url") or "https://api.shodan.io").rstrip("/"), int(cfg.get("timeout") or 90)
    op, name, tags = str(args.op or seed.get("op") or "count").lower(), str(seed["name"]), list(seed.get("tags") or [])

    if op == "host":
        ip = str(seed["query"]).strip()
        data = fetch_fn(f"{base}/shodan/host/{urllib.parse.quote(ip)}?key={key}", timeout)
        hosts = data.get("hostnames") or data.get("domains") or []
        return [make_record(name, ip, ip=ip, domain=hosts[0] if hosts else None, matches=match_patterns(json.dumps(data), patterns, args.keyword), tags=tags, raw=data)]

    q = timebox_query(str(seed["query"]), args.since_hours or cfg.get("since_hours"), args.since_days, args.from_date, args.to_date)
    qs = urllib.parse.urlencode({"key": key, "query": q})
    if op == "count":
        data = fetch_fn(f"{base}/shodan/host/count?{qs}", timeout)
        return [make_record(name, q, status=int(data.get("total", 0)), tags=tags, raw=data)]

    data = fetch_fn(f"{base}/shodan/host/search?{qs}", timeout)
    out: list[dict[str, Any]] = []
    for row in (data.get("matches") or [])[: int(cfg.get("max_results") or 50)]:
        hosts = row.get("hostnames") or row.get("domains") or []
        status = (row.get("http") or {}).get("status") if isinstance(row.get("http"), dict) else row.get("port")
        out.append(make_record(name, q, ip=row.get("ip_str"), domain=hosts[0] if hosts else None, status=status, matches=match_patterns(json.dumps(row), patterns, args.keyword), tags=tags, raw=row))
    return out


def save_records(records: list[dict[str, Any]], data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / "shodan.jsonl"
    with out_path.open("a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return out_path


def run_self_test() -> int:
    cfg = OmegaConf.to_container(OmegaConf.load(DEFAULT_CONFIG), resolve=True)
    assert isinstance(cfg, dict)
    cfg["scanner"]["api_key"] = "test-key"
    ns = argparse.Namespace(op=None, keyword="cairn", since_hours=None, since_days=7, from_date=None, to_date=None)
    fake = lambda url, t: {"total": 42} if "/count" in url else {"ip_str": "8.8.8.8", "hostnames": ["dns.google"], "banner": "https://webhook.site/12345678-1234-1234-1234-1234567890ab"}
    r1 = scan_seed(cfg["seeds"][0], cfg["scanner"], cfg["patterns"], ns, fetch_fn=fake)
    r2 = scan_seed(cfg["seeds"][-1], cfg["scanner"], cfg["patterns"], ns, fetch_fn=fake)
    assert r1[0]["status"] == 42 and set(r1[0].keys()) == {"id", "scanner", "seed", "query", "observed_at", "url", "ip", "domain", "status", "matches", "tags", "raw"}
    assert "webhook_uuid" in r2[0]["matches"]
    with tempfile.TemporaryDirectory() as tmp:
        assert save_records(r1 + r2, Path(tmp)).is_file()
    print("[shodan] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    for env in (SCRIPT_DIR / ".env", SCRIPT_DIR.parent / ".env", SCRIPT_DIR.parent.parent / ".env"):
        if env.is_file():
            load_dotenv(env, override=False)
    p = argparse.ArgumentParser(description="Shodan scanner")
    for flag, kw in [("--config", {"default": str(DEFAULT_CONFIG)}), ("-k", {"dest": "keyword"}), ("--keyword", {}), ("-q", {"dest": "query"}),
                     ("--query", {}), ("--ip", {}), ("-o", {"dest": "op", "choices": ["count", "search", "host"]}), ("--op", {"choices": ["count", "search", "host"]}),
                     ("--tag", {"action": "append", "default": []}), ("--since-hours", {"type": float}), ("--since-days", {"type": float}),
                     ("--from-date", {}), ("--to-date", {}), ("--max-runtime", {"type": float})]:
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
    if args.ip:
        seeds = [{"name": f"host_{args.ip}", "query": args.ip, "op": "host", "tags": ["adhoc"]}]
    elif args.query:
        seeds = [{"name": "adhoc_query", "query": args.query, "op": args.op or "count", "tags": ["adhoc"]}]
    elif args.keyword and not args.filter_seeds:
        tmpls = scfg.get("keyword_templates") or ['http.title:"{keyword}"', 'http.html:"{keyword}"']
        seeds = [{"name": f"kw_{i}", "query": t.replace("{keyword}", args.keyword), "op": args.op or "count", "tags": ["keyword"]} for i, t in enumerate(tmpls, 1)]
    else:
        seeds = [s for s in (cfg.get("seeds") or []) if (not args.tag or set(args.tag) & set(s.get("tags") or [])) and (not args.keyword or args.keyword.lower() in json.dumps(s).lower())]

    if args.dry_run:
        for s in seeds:
            print(json.dumps(s))
        return 0

    deadline, delay, records = time.monotonic() + float(args.max_runtime or scfg.get("max_runtime") or 300), float(scfg.get("delay") or 1.0), []
    for i, seed in enumerate(seeds):
        if time.monotonic() >= deadline:
            break
        if i > 0 and delay > 0:
            time.sleep(delay)
        records.extend(scan_seed(seed, scfg, patterns, args))

    save_records(records, (Path(args.config).parent / str(scfg.get("data_dir") or "../../data")).resolve())
    for r in records:
        print(json.dumps(r) if args.json else f"[shodan] {r['seed']} ({r['query']}) -> status={r['status']} ip={r['ip']} matches={list(r['matches'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
