import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_jsonl(records: list[dict[str, Any]], source_dir: Path, source: str, op: str) -> Path | None:
    """Deduplicate by record_id across existing JSONL files and write unseen records."""
    source_dir.mkdir(parents=True, exist_ok=True)
    seen_ids: set[str] = set()
    for path in source_dir.glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    seen_ids.add(str(json.loads(line).get("record_id")))
                except json.JSONDecodeError:
                    continue

    new_records = [r for r in records if r["record_id"] not in seen_ids]
    if not new_records:
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = source_dir / f"{source}_{op}_{ts}.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in new_records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return out_path
