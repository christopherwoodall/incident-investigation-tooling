# registry.py
from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable

SCANNERS_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = SCANNERS_DIR / "plugins"

CollectorFn = Callable[[dict[str, list[str]], dict[str, Any]], Iterable[dict[str, Any]]]


@dataclass
class PluginSpec:
    name: str
    directory: Path
    operations: dict[str, Path] = field(default_factory=dict)
    markdown_path: Path | None = None

    def read_markdown(self) -> str:
        if self.markdown_path and self.markdown_path.exists():
            return self.markdown_path.read_text(encoding="utf-8")
        ops_list = ", ".join(sorted(self.operations.keys())) or "none"
        return f"# {self.name}\n\nNo README.md found in `{self.directory}`.\nSupported operations: `{ops_list}`\n"


def discover_plugins(plugins_dir: Path = PLUGINS_DIR) -> dict[str, PluginSpec]:
    """Automatically detect plugins and supported operations from files on disk."""
    catalog: dict[str, PluginSpec] = {}
    if not plugins_dir.exists():
        return catalog

    for source_dir in sorted(plugins_dir.iterdir()):
        if not source_dir.is_dir() or source_dir.name.startswith(("_", ".")):
            continue

        ops = {
            py_file.stem: py_file
            for py_file in sorted(source_dir.glob("*.py"))
            if not py_file.name.startswith("_")
        }
        md_files = sorted(source_dir.glob("*.md"))
        readme = next((m for m in md_files if m.name.lower() == "readme.md"), md_files[0] if md_files else None)

        if ops or readme:
            catalog[source_dir.name] = PluginSpec(
                name=source_dir.name,
                directory=source_dir,
                operations=ops,
                markdown_path=readme,
            )
    return catalog


def load_operation(spec: PluginSpec, operation: str) -> CollectorFn:
    """Import plugins/<source>/<operation>.py on demand and return `collect`."""
    if operation not in spec.operations:
        supported = ", ".join(sorted(spec.operations.keys()))
        raise SystemExit(
            f"Error: '{spec.name}' does not support operation '{operation}'. "
            f"Available operation files in {spec.directory.name}/: [{supported}]"
        )

    file_path = spec.operations[operation]
    mod_name = f"plugins.{spec.name}.{operation}"
    mod_spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if mod_spec is None or mod_spec.loader is None:
        raise ImportError(f"Could not load {file_path}")

    module: ModuleType = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)

    collect_fn = getattr(module, "collect", None)
    if not callable(collect_fn):
        raise AttributeError(f"'{file_path}' must define `def collect(input_envelope, ctx):`")
    return collect_fn


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive headers before writing to output JSONL."""
    secret_keys = {"authorization", "x-api-key", "apikey", "cookie", "set-cookie"}
    return {
        k: ("***REDACTED***" if k.lower() in secret_keys else v)
        for k, v in headers.items()
    }


def build_output_envelope(
    *,
    ctx: dict[str, Any],
    permalink: str,
    http_status: int,
    headers: dict[str, str],
    content: str,
    content_type: str,
) -> dict[str, Any]:
    """Construct the standardized collector Output Envelope."""
    retrieved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content_bytes = content.encode("utf-8", errors="replace")
    content_hash = f"sha256:{hashlib.sha256(content_bytes).hexdigest()}"

    source = str(ctx["source"])
    operation = str(ctx["operation"])
    driver = str(ctx.get("driver", "api"))

    seed = f"{source}|{operation}|{permalink}|{content_hash}"
    record_id = f"sha256:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"

    return {
        "record_id": record_id,
        "retrieved_at": retrieved_at,
        "source": source,
        "operation": operation,
        "driver": driver,
        "permalink": permalink,
        "headers": redact_headers(headers),
        "http_status": int(http_status),
        "payload": {
            "content": content,
            "content_type": content_type,
            "content_hash": content_hash,
        },
    }