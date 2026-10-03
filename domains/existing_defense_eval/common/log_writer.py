"""
JSONL logger for existing-defense evaluations.

Mirrors the schema of logs in logs/<eval>/ so the rest of the analysis
pipeline can ingest these logs the same way it ingests attack-harness
logs. Logs are written to <notebook_dir>/logs/ so they live alongside
the notebook that produced them (per user requirement).
"""

import json
from pathlib import Path
from datetime import datetime, timezone


class DefenseEvalLogger:
    """JSONL writer for one defense-evaluation run."""

    def __init__(self, log_dir: Path | str, defense_id: str, domain: str,
                 extra_meta: dict | None = None):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = self.log_dir / f"{defense_id}_{domain}_{ts}.jsonl"
        self.defense_id = defense_id
        self.domain = domain
        self._meta = extra_meta or {}
        self._f = open(self.path, "a", buffering=1)
        # First line: run header
        self.log(action="run_start", **self._meta)

    def log(self, **kwargs):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "defense": self.defense_id,
            "domain": self.domain,
            **kwargs,
        }
        self._f.write(json.dumps(entry, default=str) + "\n")

    def close(self):
        self.log(action="run_end")
        if not self._f.closed:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
