import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dotenv import dotenv_values, load_dotenv
from omegaconf import OmegaConf

from collectors.registry import PluginSpec, discover_plugins, load_operation
from collectors.config import DEFAULT_CONFIG_PATH, load_merged_context
from collectors.output import save_jsonl
from collectors.envelopes import resolve_input_envelope


def print_root_help(catalog: dict[str, PluginSpec]) -> int:
    # if ROOT_README_PATH.exists():
    #     print(ROOT_README_PATH.read_text(encoding="utf-8").rstrip())
    #     print("\n---\n")
    # print("## Discovered Plugins\n")
    # for name, spec in catalog.items():
    #     ops = ", ".join(sorted(spec.operations.keys()))
    #     print(f"- **{name}**: `{ops}`")
    print("\nUsage: `collectors <source> <operation> [-q <query>]`")
    return 0


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    catalog = discover_plugins()

    # 1. Bare command or top-level help
    if not args_list or args_list[0] in {"-h", "--help", "help"}:
        return print_root_help(catalog)

    source = args_list[0]
    if source not in catalog:
        raise SystemExit(f"Error: Unknown plugin '{source}'.\nDiscovered plugins: {list(catalog.keys())}")

    plugin_spec = catalog[source]
    rest = args_list[1:]

    # 2. Bare plugin (`collectors urlquery`) or plugin help (`collectors urlquery --help` / `collectors urlquery download --help`)
    if not rest or any(flag in rest for flag in ("-h", "--help", "help")):
        print(plugin_spec.read_markdown().rstrip())
        return 0

    # 3. Parse operation and scriptable flags
    parser = argparse.ArgumentParser(prog=f"cli.py {source}", add_help=False)
    parser.add_argument("operation", choices=sorted(plugin_spec.operations.keys()))
    parser.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("-q", "--query", action="append", help="Query or URL for Input Envelope")
    parser.add_argument("--stdin", action="store_true", help='Read {"queries": [...]} from stdin')
    parser.add_argument("--limit", type=int, help="Override max records limit")
    parser.add_argument("-D", "--define", action="append", default=[], help="OmegaConf dotlist override")
    parser.add_argument("--no-save", action="store_true", help="Do not write JSONL file to disk")
    parsed = parser.parse_args(rest)

    # 4. Load collector function & merged env/YAML dictionary
    collect_fn = load_operation(plugin_spec, parsed.operation)
    ctx = load_merged_context(source, parsed.operation, parsed.config, parsed.define)

    if parsed.limit is not None:
        ctx["limit"] = parsed.limit

    if ctx.get("enabled") is False:
        raise SystemExit(
            f"Error: '{source} {parsed.operation}' is disabled in config.yaml "
            f"(surfaces.{source}.{parsed.operation}.enabled: false)."
        )

    # 5. Validate Input Envelope & run
    input_envelope = resolve_input_envelope(parsed.query, parsed.stdin, ctx)
    records = list(collect_fn(input_envelope, ctx))
    out_file = None if parsed.no_save else save_jsonl(records, ctx["output_dir"], source, parsed.operation)

    for rec in records:
        print(json.dumps(rec, ensure_ascii=False))
    print(f"[{source}:{parsed.operation}] total={len(records)} file={out_file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
