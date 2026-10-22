import os
from pathlib import Path
from typing import Any

from dotenv import dotenv_values, load_dotenv
from omegaconf import OmegaConf


CWD_DIR = Path.cwd()
REPO_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_DIR = Path(__file__).resolve().parent

DEFAULT_CONFIG_PATH = REPO_DIR / "config.yaml"

SUPPORTED_OPERATIONS = ["monitor", "search", "scan"]


def load_merged_context(
    source: str,
    operation: str,
    config_path: Path = DEFAULT_CONFIG_PATH,
    dotlist_overrides: list[str] | None = None,
) -> dict[str, Any]:
    """Load .env + host env + config.yaml (defaults -> surface -> operation) into one dict."""
    # 1. Load .env files without overwriting existing host environment variables

    repo_env = dotenv_values(REPO_DIR / ".env")
    local_env = dotenv_values(CWD_DIR / ".env")
    load_dotenv(REPO_DIR / ".env", override=False)
    load_dotenv(CWD_DIR / ".env", override=False)

    # Only expose application-specific environment variables.
    # Add other supported prefixes here if needed.
    ALLOWED_ENV_VARS = {
        "URLQUERY_API_KEY",
        "JINA_API_KEY",
        "SHODAN_API_KEY",
        "OTX_API_KEY",
    }

    merged_env: dict[str, str] = {
        k: v
        for k, v in {
            **{k: v for k, v in repo_env.items() if v is not None},
            **{k: v for k, v in local_env.items() if v is not None},
            **dict(os.environ),
        }.items()
        if v is not None and k in ALLOWED_ENV_VARS
    }

    # 2. Load and resolve OmegaConf YAML (resolves ${oc.env:...} and YAML anchors)
    if not config_path.exists():
        raise SystemExit(f"Error: Configuration file not found at {config_path}")

    raw_cfg = OmegaConf.load(config_path)
    if dotlist_overrides:
        raw_cfg = OmegaConf.merge(raw_cfg, OmegaConf.from_dotlist(dotlist_overrides))
    resolved = OmegaConf.to_container(raw_cfg, resolve=True)
    assert isinstance(resolved, dict)

    defaults = dict(resolved.get("defaults") or {})
    surfaces = dict(resolved.get("surfaces") or {})
    if source not in surfaces:
        raise SystemExit(f"Error: Surface '{source}' is not defined under 'surfaces:' in {config_path.name}.")

    surface_cfg = dict(surfaces[source] or {})
    op_cfg = dict(surface_cfg.get(operation) or {})

    # Merge headers across defaults -> surface -> operation
    merged_headers = {
        **dict(defaults.get("headers") or {}),
        **dict(surface_cfg.get("headers") or {}),
        **dict(op_cfg.get("headers") or {}),
    }

    out_cfg = dict(resolved.get("output") or {})
    out_root = (config_path.parent / str(out_cfg.get("dir", "../data"))).resolve()
    source_out_dir = out_root / source

    # Operation block (e.g., `download:`) overrides surface-level keys (like `base_url`)
    return {
        **defaults,
        **surface_cfg,
        **op_cfg,
        "source": source,
        "operation": operation,
        "headers": merged_headers,
        "output_dir": source_out_dir,
        "env": merged_env,
    }
