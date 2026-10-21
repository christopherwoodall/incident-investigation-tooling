#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
"""Standalone Wayback Machine scan stub (`wayback/scan.py`).

The Internet Archive CDX API requires a URL or domain prefix and does not
provide an unseeded global firehose feed. Running `wayback scan` logs a clear
warning to `stderr` and exits `0`.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

SCANNER_NAME = "wayback"
MODE_NAME = "scan"
SUPPORTED = False
UNSUPPORTED_REASON = (
    "Wayback Machine CDX API requires a URL or domain prefix; "
    "use 'wayback search' to run config.yaml queries or -u <url_prefix>."
)


def emit_unsupported_warning() -> int:
    """Print an unsupported-mode warning to `stderr` and return `0`.

    Returns:
        Exit code `0`.
    """
    print(
        f"[{SCANNER_NAME}] warning: '{MODE_NAME}' is not supported — {UNSUPPORTED_REASON}",
        file=sys.stderr,
    )
    return 0


def run_scan(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """Stub `run_scan` that warns on `stderr` and returns an empty list.

    Returns:
        Empty list of records.
    """
    emit_unsupported_warning()
    return []


def run_self_test() -> int:
    """Verify that `SUPPORTED` is `False` and `run_scan()` returns `[]`.

    Returns:
        Exit code `0`.
    """
    assert SUPPORTED is False
    assert run_scan() == []
    print("[wayback:scan] self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `wayback/scan.py`.

    Args:
        argv: Optional argument list.

    Returns:
        Exit code `0`.
    """
    parser = argparse.ArgumentParser(
        prog="wayback scan",
        description="Unsupported scan stub for Wayback Machine CDX API",
        add_help=True,
    )
    parser.add_argument("--self-test", action="store_true", help="Run offline self-test")
    known_args, _ = parser.parse_known_args(argv)
    if known_args.self_test:
        return run_self_test()
    return emit_unsupported_warning()


if __name__ == "__main__":
    raise SystemExit(main())
