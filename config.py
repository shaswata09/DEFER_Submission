"""
DEFER — Project Configuration

Single source of truth for base paths and environment-specific endpoints.
Nothing in the code base hard-codes a host path, an internal address or a
credential: everything below is derived from this file's location or read
from the environment (``.env`` at the repo root, see ``.env.example``).

Usage:
    from config import BASE_DIR, MODELS_DIR, LOGS_DIR, RESULTS_DIR, load_env, env_url

    manifest = BASE_DIR / "configs" / "admin_manifest.json"
    model = MODELS_DIR / "Qwen" / "Qwen3-235B-A22B-Instruct-2507"
    primary = env_url("PRIMARY_URL_Q235", "http://localhost:8000/v1")
"""

import os
import re
from pathlib import Path

# Project root — derived from this file's location
BASE_DIR = Path(__file__).resolve().parent


def load_env():
    """Load .env file from project root if it exists (idempotent)."""
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        from dotenv import load_dotenv
        load_dotenv(env_file)


load_env()



def _dir_from_env(name: str, default: Path) -> Path:
    """Directory override from the environment; relative values are
    taken relative to the repo root, not the current working directory."""
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    p = Path(v).expanduser()
    return p if p.is_absolute() else (BASE_DIR / p).resolve()


# Key directories.  MODELS_DIR / LOGS_DIR / RESULTS_DIR may be relocated
# through the environment (e.g. weights on a different volume).
MODELS_DIR = _dir_from_env("MODELS_DIR", BASE_DIR / "models")
LOGS_DIR = _dir_from_env("LOGS_DIR", BASE_DIR / "logs")
RESULTS_DIR = _dir_from_env("RESULTS_DIR", BASE_DIR / "results")
CONFIGS_DIR = BASE_DIR / "configs"

_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def expand_env(value: str) -> str:
    """Expand ``${NAME}`` and ``${NAME:-default}`` references in *value*."""
    if not isinstance(value, str):
        return value

    def _sub(m):
        name, default = m.group(1), m.group(2)
        v = os.environ.get(name)
        if v:
            return v
        if default is not None:
            return default
        raise KeyError(f"environment variable {name} is not set (see .env.example)")

    return _VAR_RE.sub(_sub, value)


def env_url(name: str, default: str | None = None) -> str:
    """Read an endpoint URL from the environment.

    Raises ``KeyError`` when the variable is missing and no default is
    given, so a misconfigured run fails before it starts instead of
    silently talking to localhost.
    """
    v = os.environ.get(name)
    if v:
        return v.rstrip("/")
    if default is not None:
        return default
    raise KeyError(f"environment variable {name} is not set (see .env.example)")


def model_display_name(model: str | None) -> str:
    """Strip host paths from a model identifier for logs and headers.

    ``/mnt/x/models/Qwen/Qwen3-32B`` -> ``Qwen/Qwen3-32B``;
    ``claude-sonnet-4-5-20250929`` is returned unchanged.
    """
    if not model:
        return str(model)
    s = str(model).replace("\\", "/")
    if "/models/" in s:
        return s.split("/models/")[-1].strip("/")
    if s.startswith("/"):
        parts = [x for x in s.split("/") if x]
        return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    return s
