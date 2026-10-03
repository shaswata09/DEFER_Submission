"""
API Budget Tracker -- enforces a $40 hard-stop across TAMAS trials.

Tracks tokens and costs across OpenAI (GPT-4o, V6) and Anthropic
(Claude, V4) API calls.  Writes per-call usage to ``results/budget.jsonl``
and raises :class:`BudgetExceededError` if cumulative cost ever exceeds
``BUDGET_HARD_STOP_USD``.

The tracker resumes from existing logs on startup so the budget is
honoured across separate trial processes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

# ---------------------------------------------------------------------- #
#  Pricing (as of 2026)
# ---------------------------------------------------------------------- #

BUDGET_HARD_STOP_USD: float = 40.0
WARNING_THRESHOLD: float = 0.80  # Warn at 80 % of budget

# OpenAI GPT-4o pricing
GPT4O_INPUT_USD_PER_1K: float = 0.0025
GPT4O_OUTPUT_USD_PER_1K: float = 0.0100

# Anthropic Claude Sonnet pricing
CLAUDE_SONNET_INPUT_USD_PER_1K: float = 0.003
CLAUDE_SONNET_OUTPUT_USD_PER_1K: float = 0.015


# ---------------------------------------------------------------------- #
#  Exceptions
# ---------------------------------------------------------------------- #


class BudgetExceededError(RuntimeError):
    """Raised when a tracked API call pushes cumulative cost over the cap."""


# ---------------------------------------------------------------------- #
#  Budget Tracker
# ---------------------------------------------------------------------- #


class BudgetTracker:
    """Cumulative cost tracker that persists per-call usage to JSONL."""

    def __init__(
        self,
        log_path: Union[str, Path] = "benchmarks/tamas/results/budget.jsonl",
        hard_stop_usd: float = BUDGET_HARD_STOP_USD,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.hard_stop_usd = float(hard_stop_usd)
        self.total_cost_usd: float = 0.0
        self._warned: bool = False
        self._load_existing()

    # ------------------------------------------------------------------ #
    #  Persistence
    # ------------------------------------------------------------------ #

    def _load_existing(self) -> None:
        """Resume tracking from a pre-existing budget.jsonl (if any)."""
        if not self.log_path.exists():
            return
        try:
            with open(self.log_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.total_cost_usd += float(entry.get("cost_usd", 0.0) or 0.0)
        except OSError:
            # Log file exists but is unreadable; start fresh silently.
            self.total_cost_usd = 0.0

    # ------------------------------------------------------------------ #
    #  Public tracking API
    # ------------------------------------------------------------------ #

    def track_openai(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        trial_id: str = "",
    ) -> float:
        """Record an OpenAI API call and return its cost in USD."""
        model_l = (model or "").lower()
        if "gpt-4o" in model_l or model_l.startswith("v6"):
            cost = (
                input_tokens / 1000.0 * GPT4O_INPUT_USD_PER_1K
                + output_tokens / 1000.0 * GPT4O_OUTPUT_USD_PER_1K
            )
        else:
            cost = 0.0
        self._record("openai", model, input_tokens, output_tokens, cost, trial_id)
        self._check_budget()
        return cost

    def track_anthropic(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        trial_id: str = "",
    ) -> float:
        """Record an Anthropic API call and return its cost in USD."""
        model_l = (model or "").lower()
        if "claude" in model_l or model_l.startswith("v4"):
            cost = (
                input_tokens / 1000.0 * CLAUDE_SONNET_INPUT_USD_PER_1K
                + output_tokens / 1000.0 * CLAUDE_SONNET_OUTPUT_USD_PER_1K
            )
        else:
            cost = 0.0
        self._record("anthropic", model, input_tokens, output_tokens, cost, trial_id)
        self._check_budget()
        return cost

    # ------------------------------------------------------------------ #
    #  Internal
    # ------------------------------------------------------------------ #

    def _record(
        self,
        provider: str,
        model: str,
        in_tok: int,
        out_tok: int,
        cost: float,
        trial_id: str,
    ) -> None:
        self.total_cost_usd += float(cost)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "input_tokens": int(in_tok),
            "output_tokens": int(out_tok),
            "cost_usd": round(float(cost), 6),
            "cumulative_usd": round(self.total_cost_usd, 6),
            "trial_id": trial_id,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _check_budget(self) -> None:
        if self.total_cost_usd >= self.hard_stop_usd:
            raise BudgetExceededError(
                f"Budget exceeded: ${self.total_cost_usd:.2f} "
                f">= ${self.hard_stop_usd:.2f}"
            )
        if (
            not self._warned
            and self.total_cost_usd >= self.hard_stop_usd * WARNING_THRESHOLD
        ):
            self._warned = True
            pct = self.total_cost_usd / self.hard_stop_usd
            print(
                f"WARNING: Budget at {pct:.0%} "
                f"(${self.total_cost_usd:.2f}/${self.hard_stop_usd:.2f})"
            )

    # ------------------------------------------------------------------ #
    #  Reporting
    # ------------------------------------------------------------------ #

    def summary(self) -> dict:
        """Return a small report dict (used by trial finalizers)."""
        return {
            "total_cost_usd": round(self.total_cost_usd, 4),
            "remaining_usd": round(self.hard_stop_usd - self.total_cost_usd, 4),
            "hard_stop_usd": self.hard_stop_usd,
            "percent_used": round(
                (self.total_cost_usd / self.hard_stop_usd * 100) if self.hard_stop_usd else 0.0,
                1,
            ),
        }


__all__ = [
    "BudgetTracker",
    "BudgetExceededError",
    "BUDGET_HARD_STOP_USD",
    "WARNING_THRESHOLD",
    "GPT4O_INPUT_USD_PER_1K",
    "GPT4O_OUTPUT_USD_PER_1K",
    "CLAUDE_SONNET_INPUT_USD_PER_1K",
    "CLAUDE_SONNET_OUTPUT_USD_PER_1K",
]
