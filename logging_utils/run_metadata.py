"""Run-header metadata for experiment logs.

Every JSONL log written by :class:`ExperimentLogger` starts with a
``run_header`` event that pins the run to a code version, a model set and
the sampling settings, so a results table can always be traced back to
exactly what produced it.  This module collects that metadata.

Fields (``None`` when unknown at the time the log is opened; later tasks
fill in ``primary_temperature``, ``seed`` and ``state_mode``):

    git_sha, git_dirty, freeze_tag, group, config, domain,
    primary_model, primary_quantization, validator_models, consensus_config,
    consensus_threshold, vllm_version, primary_temperature, seed, state_mode, trials,
    disabled_principles, command

Model identifiers are always passed through
:func:`config.model_display_name` so no host path ends up in a log.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Any, Optional

from config import BASE_DIR, CONFIGS_DIR, model_display_name

HEADER_FIELDS = (
    "git_sha", "git_dirty", "freeze_tag", "group", "config", "domain",
    "primary_model", "primary_quantization", "validator_models",
    "consensus_config", "consensus_threshold", "vllm_version", "primary_temperature", "seed",
    "state_mode", "trials", "disabled_principles", "command",
)

FREEZE_TAG_PREFIX = "defense-freeze-"


def _git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", *args], cwd=BASE_DIR, capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


# Run outputs live under the tree but a run writing them does not make the
# source "dirty"; the dirty flag is about code / payloads / configs.
_OUTPUT_DIRS = ("results/", "logs/", "data/")


def git_state() -> dict[str, Any]:
    """Current commit, whether the *source* tree is dirty, and the freeze tag.

    ``git_dirty`` ignores tracked changes under results/ logs/ data/ (a run
    rewrites those), so a run launched from committed source records
    ``git_dirty=false`` even while it is producing output.
    """
    sha = _git("rev-parse", "HEAD")
    dirty = None
    if sha:
        status = _git("status", "--porcelain", "--untracked-files=no") or ""
        src = []
        for ln in status.splitlines():
            # porcelain is "XY <path>"; _git strips the first line's leading
            # status space, so take the path as the last whitespace-run token
            # (rename "a -> b" keeps b, still fine for the output-dir check).
            parts = ln.strip().split(maxsplit=1)
            path = parts[1].split(" -> ")[-1] if len(parts) == 2 else ""
            if not any(path.startswith(d) for d in _OUTPUT_DIRS):
                src.append(ln)
        dirty = bool(src)
    # The freeze tag is the most recent defense-freeze-* tag reachable from
    # HEAD.  ``git describe --exact-match`` reports whether HEAD *is* the
    # frozen commit; otherwise we record the nearest one with a distance.
    tag = _git("describe", "--tags", "--exact-match", "--match", f"{FREEZE_TAG_PREFIX}*")
    if tag is None:
        near = _git("describe", "--tags", "--match", f"{FREEZE_TAG_PREFIX}*", "--long")
        tag = near  # e.g. defense-freeze-v2-3-gabc1234 (3 commits after the tag)
    return {"git_sha": sha, "git_dirty": dirty, "freeze_tag": tag}


def _env_redactions() -> list[tuple[str, str]]:
    """``(secret_value, "<ENV_NAME>")`` pairs for sensitive environment values.

    Covers API keys / tokens / secrets and remote (non-localhost) endpoint URLs
    such as ``REMOTE_5090_URL`` -- these reach ``sys.argv`` when a run is invoked
    with ``--model-url $REMOTE_5090_URL`` / ``--api-key ...`` and must never land
    in a committed log. Longest values first so a value that is a substring of
    another is not clobbered.
    """
    reds: dict[str, str] = {}
    for name, val in os.environ.items():
        v = (val or "").strip()
        if len(v) < 6:                       # too short to be a real secret / URL
            continue
        upper = name.upper()
        if upper.endswith(("KEY", "TOKEN", "SECRET", "PASSWORD")):
            reds[v] = f"<{name}>"
        elif "://" in v and not re.search(r"://(localhost|127\.0\.0\.1)\b", v):
            reds[v] = f"<{name}>"            # remote endpoint (localhost is not secret)
    return sorted(reds.items(), key=lambda kv: -len(kv[0]))


def _scrubbed_command() -> str:
    """``sys.argv`` with the repo root replaced by ``<repo>`` and any sensitive
    environment values (keys, remote endpoint URLs) redacted, so the header
    never records an absolute host path or a secret."""
    root = str(BASE_DIR)
    args = [a.replace(root, "<repo>") for a in sys.argv]
    for secret, placeholder in _env_redactions():
        args = [a.replace(secret, placeholder) for a in args]
    return " ".join(args)


def quantization_from_model_id(model_id: Optional[str]) -> Optional[str]:
    """Infer the weight format from the model identifier.

    The vLLM servers in this project load the checkpoints as stored: FP8
    checkpoints carry ``FP8`` in their name, everything else is BF16.
    ``PRIMARY_QUANTIZATION`` in the environment overrides the guess.
    """
    override = os.environ.get("PRIMARY_QUANTIZATION")
    if override:
        return override
    if not model_id:
        return None
    return "fp8" if "fp8" in model_id.lower() else "bf16"


def probe_openai_server(base_url: Optional[str], api_key_env: Optional[str] = None,
                        timeout: float = 3.0) -> dict[str, Any]:
    """Best-effort probe of an OpenAI-compatible endpoint.

    Returns ``{"served_model": <id or None>, "vllm_version": <str or None>}``.
    Never raises: a run must be able to start while the server is still
    loading, and API providers do not expose these endpoints.
    """
    out: dict[str, Any] = {"served_model": None, "vllm_version": None}
    if not base_url or not base_url.startswith("http"):
        return out
    try:
        import httpx
    except ImportError:
        return out
    headers = {}
    key = os.environ.get(api_key_env, "") if api_key_env else ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    root = base_url.rstrip("/")
    server_root = root[:-3] if root.endswith("/v1") else root
    try:
        r = httpx.get(f"{root}/models", headers=headers, timeout=timeout)
        if r.status_code == 200:
            data = r.json().get("data") or []
            if data:
                out["served_model"] = model_display_name(data[0].get("id"))
    except Exception:
        pass
    try:
        r = httpx.get(f"{server_root}/version", headers=headers, timeout=timeout)
        if r.status_code == 200:
            out["vllm_version"] = (r.json() or {}).get("version")
    except Exception:
        pass
    return out


def validator_panel_for(consensus_config: Optional[str]) -> tuple[Optional[dict], Optional[int]]:
    """``({validator_id: model_id}, threshold)`` for a panel in configs/validators.yaml.

    Panels are top-level keys of the file with ``validators`` (ids) and
    ``threshold``; the ``validators:`` section maps ids to endpoints/models.
    """
    if not consensus_config:
        return None, None
    try:
        import yaml
        with open(CONFIGS_DIR / "validators.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        panel = cfg.get(consensus_config)
        if not isinstance(panel, dict) or "validators" not in panel:
            return None, None
        registry = cfg.get("validators") or {}
        models = {vid: model_display_name((registry.get(vid) or {}).get("model"))
                  for vid in panel.get("validators", [])}
        return models, panel.get("threshold")
    except Exception:
        return None, None


def assert_frozen(header: dict) -> None:
    """Abort unless the defense code equals the freeze tag.

    Accepts HEAD == tag, or a later commit whose frozen directories are
    byte-identical to the tag (analysis / scripts may keep changing).  The
    tree must be clean in the frozen directories.
    """
    tag = header.get("freeze_tag") or ""
    if not re.fullmatch(rf"{FREEZE_TAG_PREFIX}[A-Za-z0-9.]+", tag):
        # not exactly on the tag: fall back to the directory comparison
        check = BASE_DIR / "scripts" / "check_freeze.sh"
        rc = subprocess.run(["bash", str(check)], cwd=BASE_DIR, capture_output=True, text=True)
        if rc.returncode != 0:
            raise SystemExit("--require-freeze: defense code differs from the freeze tag:\n" + rc.stdout)
        return
    if header.get("git_dirty"):
        rc = subprocess.run(["bash", str(BASE_DIR / "scripts" / "check_freeze.sh")], cwd=BASE_DIR,
                            capture_output=True, text=True)
        if rc.returncode != 0:
            raise SystemExit("--require-freeze: uncommitted changes in frozen directories:\n" + rc.stdout)


def build_run_header(
    *,
    group: Optional[str] = None,
    config: Optional[str] = None,
    domain: Optional[str] = None,
    primary_url: Optional[str] = None,
    primary_provider: str = "openai",
    primary_model: Optional[str] = None,
    api_key_env: Optional[str] = None,
    consensus_config: Optional[str] = None,
    primary_temperature: Optional[float] = None,
    seed: Optional[int] = None,
    state_mode: Optional[str] = None,
    trials: Optional[int] = None,
    disabled_principles: Optional[set] = None,
    probe: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    """Assemble the ``run_header`` payload.

    ``primary_model`` wins over the served model reported by the endpoint;
    the endpoint is only probed when nothing better is known.
    """
    header: dict[str, Any] = {k: None for k in HEADER_FIELDS}
    header.update(git_state())
    header.update({
        "group": group, "config": config, "domain": domain,
        "consensus_config": consensus_config,
        "primary_temperature": primary_temperature, "seed": seed,
        "state_mode": state_mode, "trials": trials,
        "disabled_principles": sorted(disabled_principles) if disabled_principles else [],
        "command": _scrubbed_command(),
    })
    served = probe_openai_server(primary_url, api_key_env) if (probe and primary_provider != "anthropic") else {}
    header["primary_model"] = model_display_name(primary_model) if primary_model else served.get("served_model")
    if primary_provider == "anthropic" and not header["primary_model"]:
        header["primary_model"] = "claude-sonnet-4-5-20250929"
    header["primary_quantization"] = (
        "api" if primary_provider == "anthropic" else quantization_from_model_id(header["primary_model"]))
    header["vllm_version"] = served.get("vllm_version")
    header["validator_models"], header["consensus_threshold"] = validator_panel_for(consensus_config)
    header.update(extra)
    return header
