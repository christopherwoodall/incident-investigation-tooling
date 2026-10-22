#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["omegaconf>=2.3.0", "python-dotenv>=1.0.0"]
# ///
import sys

from pathlib import Path

from omegaconf import OmegaConf


cfg = OmegaConf.load("config.yaml")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    invoked_name = Path(sys.argv[0]).stem
    print(f"Invoked as: {invoked_name}")

    if not args or args[0] in {"-h", "--help"}:
        print("Usage: python cli.py <scanner> <search|scan> [options]\nAvailable: jina search, jina scan")
        return 0 if args else 2

    for name, surface_cfg in cfg.surfaces.items():
        # Deep-merges defaults with the specific surface (surface overwrites defaults)
        # Unlike YAML's '<<', OmegaConf.merge() DOES deep-merge nested dicts like 'headers'!
        effective_surface = OmegaConf.merge(cfg.defaults, surface_cfg)
        print(f"Surface: {name}")
        print(f"  Effective configuration: {OmegaConf.to_yaml(effective_surface)}")


if __name__ == "__main__":
    raise SystemExit(main())


# """General CLI launcher for all incident-investigation scanners.

# This module provides a unified command-line entrypoint (`scanners`) as well as
# per-scanner console aliases (`shodan`, `urlquery`, `yourls`, `jina`, `wayback`,
# `urlscan`, `crtsh`, `ntfy`, `reposcout`, `packages`). Each scanner directory
# contains two standalone `uv` scripts (`scan.py` and `search.py`) that this
# launcher loads and executes dynamically.
# """

# from __future__ import annotations

# import argparse
# import importlib.util
# import sys
# from pathlib import Path
# from types import ModuleType

# SCANNERS_DIRECTORY = Path(__file__).resolve().parent
# AVAILABLE_SCANNERS: tuple[str, ...] = (
#     "shodan",
#     "urlquery",
#     "yourls",
#     "jina",
#     "wayback",
#     "urlscan",
#     "crtsh",
#     "ntfy",
#     "reposcout",
#     "packages",
# )
# VALID_MODES: tuple[str, ...] = ("scan", "search")


# def load_scanner_script(scanner_name: str, mode_name: str) -> ModuleType:
#     """Dynamically load a scanner's `scan.py` or `search.py` script module.

#     Args:
#         scanner_name: Name of the scanner subdirectory (for example, `"urlquery"`).
#         mode_name: Script mode to load (`"scan"` or `"search"`).

#     Returns:
#         The loaded Python module object for `<scanner_name>/<mode_name>.py`.
#     """
#     script_path = SCANNERS_DIRECTORY / scanner_name / f"{mode_name}.py"
#     module_identifier = f"scanner_{scanner_name}_{mode_name}"
#     module_spec = importlib.util.spec_from_file_location(module_identifier, script_path)
#     assert module_spec is not None and module_spec.loader is not None
#     loaded_module = importlib.util.module_from_spec(module_spec)
#     module_spec.loader.exec_module(loaded_module)
#     return loaded_module


# def print_scanner_table() -> int:
#     """Print a summary table of all available scanners and their supported modes.

#     Returns:
#         Exit code `0`.
#     """
#     header_line = f"{'SCANNER':<12} {'SCAN':<12} {'SEARCH':<12} {'SCRIPT DIRECTORY'}"
#     print(header_line)
#     print("-" * len(header_line))
#     for scanner_name in AVAILABLE_SCANNERS:
#         scan_module = load_scanner_script(scanner_name, "scan")
#         search_module = load_scanner_script(scanner_name, "search")
#         scan_status = "supported" if getattr(scan_module, "SUPPORTED", True) else "unsupported"
#         search_status = "supported" if getattr(search_module, "SUPPORTED", True) else "unsupported"
#         scanner_folder = SCANNERS_DIRECTORY / scanner_name
#         print(f"{scanner_name:<12} {scan_status:<12} {search_status:<12} {scanner_folder}")
#     return 0


# def run_scanner_self_tests(target_scanners: list[str] | None = None) -> int:
#     """Run offline self-tests for `scan.py` and `search.py` across scanners.

#     Args:
#         target_scanners: Optional subset of scanner names to test. When omitted
#             or empty, all scanners in `AVAILABLE_SCANNERS` are tested.

#     Returns:
#         Exit code `0` if every self-test passes, or `1` if any test fails.
#     """
#     scanners_to_test = target_scanners or list(AVAILABLE_SCANNERS)
#     for scanner_name in scanners_to_test:
#         for mode_name in VALID_MODES:
#             script_module = load_scanner_script(scanner_name, mode_name)
#             exit_code = int(script_module.run_self_test())
#             if exit_code != 0:
#                 return exit_code
#     return 0


# def dispatch_single_scanner(scanner_name: str, argument_list: list[str]) -> int:
#     """Dispatch CLI arguments to a specific scanner's `scan.py` or `search.py`.

#     Args:
#         scanner_name: Name of the target scanner directory.
#         argument_list: Arguments following the scanner name.

#     Returns:
#         Process exit code from the target script or self-test runner.
#     """
#     if "--self-test" in argument_list:
#         return run_scanner_self_tests([scanner_name])

#     if not argument_list:
#         mode_name = "scan"
#         forwarded_arguments: list[str] = []
#     elif argument_list[0] in VALID_MODES:
#         mode_name = argument_list[0]
#         forwarded_arguments = argument_list[1:]
#     elif argument_list[0] in ("-h", "--help"):
#         parser = argparse.ArgumentParser(
#             prog=scanner_name,
#             description=(
#                 f"Launcher for the '{scanner_name}' scanner. "
#                 f"Specify 'scan' or 'search' followed by script flags."
#             ),
#         )
#         parser.add_argument("mode", choices=VALID_MODES, help="Execution mode ('scan' or 'search')")
#         parser.add_argument(
#             "--self-test",
#             action="store_true",
#             help=f"Run offline self-tests for {scanner_name}/scan.py and {scanner_name}/search.py",
#         )
#         parser.print_help()
#         return 0
#     else:
#         mode_name = "scan"
#         forwarded_arguments = argument_list

#     target_module = load_scanner_script(scanner_name, mode_name)
#     return int(target_module.main(forwarded_arguments))


# def build_general_parser() -> argparse.ArgumentParser:
#     """Construct the top-level argument parser for `./scanners/cli.py`.

#     Returns:
#         Configured `argparse.ArgumentParser` instance.
#     """
#     parser = argparse.ArgumentParser(
#         prog="scanners",
#         description=(
#             "General launcher for all incident-investigation scanners. "
#             "Usage: scanners <scanner> <scan|search> [options...]"
#         ),
#     )
#     parser.add_argument(
#         "--list",
#         action="store_true",
#         help="List all available scanners and their scan/search support status",
#     )
#     parser.add_argument(
#         "--self-test",
#         action="store_true",
#         help="Run offline self-tests across all scanners (or a specified scanner)",
#     )
#     parser.add_argument(
#         "scanner",
#         nargs="?",
#         choices=AVAILABLE_SCANNERS,
#         help="Scanner directory to run",
#     )
#     parser.add_argument(
#         "mode",
#         nargs="?",
#         choices=VALID_MODES,
#         help="Mode to execute ('scan' or 'search')",
#     )
#     return parser


# def main(argv: list[str] | None = None) -> int:
#     """Entrypoint for the unified `scanners` CLI launcher and per-tool aliases.

#     Args:
#         argv: Optional list of CLI arguments. Defaults to `sys.argv[1:]`.

#     Returns:
#         Exit status code (`0` for success, non-zero on error).
#     """
#     argument_list = list(sys.argv[1:] if argv is None else argv)
#     invoked_name = Path(sys.argv[0]).stem
#     if argv is None and invoked_name in AVAILABLE_SCANNERS:
#         return dispatch_single_scanner(invoked_name, argument_list)

#     if "--list" in argument_list:
#         return print_scanner_table()

#     if argument_list and argument_list[0] in AVAILABLE_SCANNERS:
#         return dispatch_single_scanner(argument_list[0], argument_list[1:])

#     if "--self-test" in argument_list:
#         return run_scanner_self_tests()

#     build_general_parser().print_help()
#     return 0


# if __name__ == "__main__":
#     raise SystemExit(main())
