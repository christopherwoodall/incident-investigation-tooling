#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Self-contained Jina AI reader (r.jina.ai) scanner with unified 12-field output."""
from __future__ import annotations

import argparse, hashlib, json, os, re, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
from omegaconf import OmegaConf

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"


def match_patterns(text: str, patterns: dict[str, str], keyword: str | None = None) -> dict[str, list[str]]:
    decoded = urllib.parse.unquote(text)
    haystack = text if decoded == text else f"{text}\n{decoded}"
    matches = {
        name: hits[:25]
        for name, expr in (patterns or {}).items()
        if (hits := sorted({(m.group(1) if m.lastindex else m.group(0)).strip()[:80] for m in re.finditer(expr, haystack)} - {""}))
    }
    if keyword and keyword.lower() in haystack.lower():
        matches["keyword"] = [keyword]
    return matches


def make_record(seed: str, query: str, *, url: str | None = None, ip: str | None = None, domain: str | None = None,
                status: int | None = None, matches: dict[str, list[str]] | None = None, tags: list[str] | None = None, raw: Any = None) -> dict[str, Any]:
    key = f"jina|{seed}|{query}|{url}|{ip}|{json.dumps(raw, sort_keys=True, default=str)[:200]}"
    return {
        "id": f"jina:{hashlib.sha256(key.encode()).hexdigest()[:12]}",
        "scanner": "jina", "seed": seed, "query": query,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url, "ip": ip, "domain": domain, "status": status,
        "matches": matches or {}, "tags": list(dict.fromkeys([*(tags or []), *(matches or {}).keys()])), "raw": raw,
    }


def http_get_jina(url: str, timeout: int, max_bytes: int, api_key: str = "") -> tuple[int, str | None]:
    headers = {"User-Agent": "incident-scanner/1.0", "Accept": "text/plain", "X-Return-Format": "text"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            return int(getattr(resp, "status", 200)), resp.read(max_bytes).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), None
    except Exception:
        return -1, None


def scan_seed(seed: dict[str, Any], cfg: dict[str, Any], patterns: dict[str, str], args: argparse.Namespace, fetch_fn=http_get_jina) -> list[dict[str, Any]]:
    target = str(seed["query"]).strip()
    base = str(cfg.get("base_url") or "https://r.jina.ai/").rstrip("/") + "/"
    key = str(cfg.get("api_key") or os.environ.get("JINA_API_KEY") or "").strip()
    timeout, max_bytes = int(cfg.get("timeout") or 120), int(cfg.get("max_bytes") or 200000)

    status, text = -1, None
    for wait in [0, *(cfg.get("retry_sleeps") or [60, 120])]:
        if wait > 0:
            time.sleep(float(wait))
        status, text = fetch_fn(base + target, timeout, max_bytes, key)
        if (status == 200 and text is not None) or status != 429:
            break

    if text is None:
        return []
    hits = match_patterns(text, patterns, args.keyword)
    return [make_record(str(seed["name"]), target, url=base + target, domain=urllib.parse.urlparse(target).hostname, status=status, matches=hits, tags=list(seed.get("tags") or []), raw={"target_url": target, "chars": len(text), "text": text})]


def save_records(records: list[dict[str, Any]], data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / "jina.jsonl"
    with out_path.open("a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return out_path


def run_self_test() -> int:
    cfg = OmegaConf.to_container(OmegaConf.load(DEFAULT_CONFIG), resolve=True)
    assert isinstance(cfg, dict)
    cfg["scanner"]["retry_sleeps"] = [0, 0]
    calls: list[str] = []
    txt = "https://webhook.site/12345678-1234-1234-1234-1234567890ab uqscan=claude20261019 ntfy.sh/amapdata_drop"
    fake = lambda u, t, m, k: (calls.append(u), (429, None) if len(calls) == 1 else (200, txt))[1]
    recs = scan_seed(cfg["seeds"][0], cfg["scanner"], cfg["patterns"], argparse.Namespace(keyword="claude20261019"), fetch_fn=fake)
    assert len(calls) == 2 and len(recs) == 1 and set(recs[0].keys()) == {"id", "scanner", "seed", "query", "observed_at", "url", "ip", "domain", "status", "matches", "tags", "raw"}
    assert recs[0]["matches"]["webhook_uuid"] == ["12345678-1234-1234-1234-1234567890ab"] and recs[0]["matches"]["tag_param"] == ["claude20261019"]
    with tempfile.TemporaryDirectory() as tmp:
        assert save_records(recs, Path(tmp)).is_file()
    print("[jina] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    for env in (SCRIPT_DIR / ".env", SCRIPT_DIR.parent / ".env", SCRIPT_DIR.parent.parent / ".env"):
        if env.is_file():
            load_dotenv(env, override=False)
    p = argparse.ArgumentParser(description="Jina AI reader (r.jina.ai) scanner")
    for flag, kw in [("--config", {"default": str(DEFAULT_CONFIG)}), ("-u", {"dest": "url"}), ("--url", {}), ("-k", {"dest": "keyword"}),
                     ("--keyword", {}), ("--tag", {"action": "append", "default": []}), ("--since-hours", {"type": float}), ("--max-runtime", {"type": float})]:
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

    deadline, delay, records = time.monotonic() + float(args.max_runtime or scfg.get("max_runtime") or 600), float(scfg.get("delay") or 10.0), []
    for i, seed in enumerate(seeds):
        if time.monotonic() >= deadline:
            break
        if i > 0 and delay > 0:
            time.sleep(delay)
        records.extend(scan_seed(seed, scfg, patterns, args))

    save_records(records, (Path(args.config).parent / str(scfg.get("data_dir") or "../../data")).resolve())
    for r in records:
        print(json.dumps(r) if args.json else f"[jina] {r['seed']} ({r['query']}) -> status={r['status']} matches={list(r['matches'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
