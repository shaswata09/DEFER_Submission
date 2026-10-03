"""Which log files belong to a run: one definition for every analysis.

A log file belongs to (group, domain, config) when

* its group is its log directory's group, unless ``run_groups.yaml`` routes
  the file elsewhere (a later experiment that reused a main group's directory),
  and
* its config is exactly ``config`` as written in the file's ``run_header``.

Selecting on the file name instead is what went wrong before: the pattern
``agenticcyops_*.jsonl`` also matches ``agenticcyops_writejudge_*``,
``agenticcyops_gate_permissive_*`` and ``agenticcyops_noautoapprove_*``, and a
directory glob ``*_eval_attacks_<group>*`` also matches ``<group>_e9`` and
``<group>_persistent``. Every analysis that reads logs should go through
:func:`run_logs` or :func:`config_files`.
"""
from __future__ import annotations

import functools
import json
import re
from pathlib import Path

from config import LOGS_DIR

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
DIR_RE = re.compile(r"^(cyberops|healthcare|finance|legal)_eval_attacks_(.+?)(_disabled_[A-Z0-9]+)?$")
RUN_GROUPS_FILE = Path(__file__).with_name("run_groups.yaml")
# <config>_<YYYYMMDD>_<HHMMSS>.jsonl -- used only when a log has no run_header
_NAME_RE = re.compile(r"^(?P<config>.+)_\d{8}_\d{6}\.jsonl$")


@functools.lru_cache(maxsize=1)
def load_run_groups(path: Path = RUN_GROUPS_FILE) -> dict[str, str]:
    """``<log dir>/<file>`` -> group, for the runs listed in run_groups.yaml."""
    if not path.exists():
        return {}
    import yaml
    spec = yaml.safe_load(path.read_text()) or {}
    return {log: group for group, entry in spec.items() for log in entry.get("logs", [])}


@functools.lru_cache(maxsize=None)
def header_config(path: Path) -> str:
    """The ``config`` of a log file, from its run_header; from the file name
    (``<config>_<date>_<time>.jsonl``) for logs that predate the header."""
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i > 50:
                    break
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("action") == "run_header" and e.get("config"):
                    return str(e["config"])
    except OSError:
        pass
    m = _NAME_RE.match(path.name)
    return m.group("config") if m else ""


def file_group(path: Path) -> tuple[str, str, str] | None:
    """(domain, group, suffix) a log file belongs to, after routing."""
    m = DIR_RE.match(path.parent.name)
    if not m:
        return None
    domain, group, suffix = m.group(1), m.group(2), m.group(3) or ""
    return domain, load_run_groups().get(f"{path.parent.name}/{path.name}", group), suffix


def config_files(log_dir: Path, config: str) -> list[Path]:
    """Log files in one directory whose header config is exactly ``config``."""
    return [p for p in sorted(Path(log_dir).glob("*.jsonl")) if header_config(p) == config]


def run_logs(group: str, domain: str, config: str | None = None, suffix: str = "",
             logs_dir: Path = LOGS_DIR) -> list[Path]:
    """Every log file of (group, domain[, config]) after routing.

    Looks in every directory of the domain, not only ``<domain>_eval_attacks_
    <group>``, because routing can move a file out of the directory it sits in.

    The virtual group ``analysis.reported.REPORTED`` resolves to its member
    groups' files in time order (``<config>_<date>_<time>.jsonl``), so a reader
    that keeps the newest file per trial takes the re-run cell.
    """
    from analysis.reported import COMPOSITION, REPORTED
    if group == REPORTED:
        members = [p for g in COMPOSITION.get(domain, ()) for p in
                   run_logs(g, domain, config, suffix, logs_dir)]
        return sorted(members, key=lambda p: (_stamp(p), str(p)))
    out = []
    for d in sorted(Path(logs_dir).glob(f"{domain}_eval_attacks_*")):
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.jsonl")):
            fg = file_group(p)
            if fg is None or fg != (domain, group, suffix):
                continue
            if config is not None and header_config(p) != config:
                continue
            out.append(p)
    return out


def _stamp(path: Path) -> str:
    """``YYYYMMDD_HHMMSS`` of a log file name, for ordering runs in time."""
    m = re.search(r"_(\d{8}_\d{6})\.jsonl$", path.name)
    return m.group(1) if m else ""
