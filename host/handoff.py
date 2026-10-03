"""
Inter-phase context passing.

Packages each phase's outputs into structured context for the next phase.
Domain-agnostic — works with any agent output format.
Sanitizes handoff text for prompt injection (TA-23 / Fix #9).
"""

import re
from datetime import datetime, timezone
from typing import Optional

from logging_utils import ExperimentLogger

# Injection patterns to strip from handoff text (same as P5-L5)
_INJECTION_PATTERNS = [
    re.compile(p) for p in [
        r"(?i)(ignore|disregard|override)\s+(previous|above|all)\s+(instructions?|prompts?|rules?)",
        r"(?i)you\s+(must|should|need\s+to)\s+(immediately|urgently|now)\s+(call|invoke|use|execute)",
        r"(?i)(system\s+update|policy\s+override|mandatory\s+action|emergency\s+protocol)",
        r"(?i)respond\s+with\s+(only|just)\s+(approve|yes|confirm)",
        r"(?i)(do\s+not|don't)\s+(create|open|make)\s+a?\s*ticket",
        r"(?i)skip\s+(standard|normal|regular)\s+(triage|procedure|process|workflow)",
        r"(?i)authorization\s+(code|token|badge)\s*[:=]",
        r"(?i)(note|instruction)\s+(to|for)\s+(validator|analyst|agent|admin)",
        r"(?i)(pre-?approved|rubber.?stamp)",
        r"(?i)(system\s+override|security\s+override|admin\s+override)\s*:",
    ]
]


def _sanitize_text(text: str) -> tuple[str, int]:
    """Strip injection patterns from text. Returns (sanitized, count)."""
    if not isinstance(text, str):
        return str(text), 0
    count = 0
    for pattern in _INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            count += len(matches)
            text = pattern.sub("[REDACTED — POTENTIAL INJECTION]", text)
    return text, count


class PhaseHandoff:
    """Manages inter-phase context passing."""

    def __init__(self, logger: Optional[ExperimentLogger] = None):
        self.logger = logger

    def create_handoff(
        self,
        source_phase: str,
        target_phase: str,
        phase_output: dict,
        incident_context: dict,
    ) -> dict:
        """Package phase output as enriched context for the next phase.

        Args:
            source_phase: Phase that just completed ("monitor", "analyze", etc.)
            target_phase: Phase about to start
            phase_output: The completed phase's AgentResult as dict
            incident_context: Running incident context
        """
        # Sanitize text fields for prompt injection (Fix #9)
        summary, s_count = _sanitize_text(phase_output.get("summary", ""))
        reasoning, r_count = _sanitize_text(phase_output.get("reasoning", ""))
        injection_count = s_count + r_count

        # Sanitize tool_results for injection (Fix: second-pass finding #3)
        raw_tool_results = phase_output.get("tool_responses", [])
        sanitized_tool_results = []
        for tr in raw_tool_results:
            if isinstance(tr, dict):
                tr_copy = dict(tr)
                for key in ("result", "output", "data", "message", "detail"):
                    if key in tr_copy and isinstance(tr_copy[key], str):
                        tr_copy[key], c = _sanitize_text(tr_copy[key])
                        injection_count += c
                sanitized_tool_results.append(tr_copy)
            elif isinstance(tr, str):
                cleaned, c = _sanitize_text(tr)
                injection_count += c
                sanitized_tool_results.append(cleaned)
            else:
                sanitized_tool_results.append(tr)

        handoff = {
            "source_phase": source_phase,
            "target_phase": target_phase,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident_context.get("incident_id"),
            "phase_summary": summary,
            "phase_reasoning": reasoning,
            "tool_results": sanitized_tool_results,
            "memory_reads": [
                {k: (_sanitize_text(v)[0] if isinstance(v, str) else v)
                 for k, v in (mr if isinstance(mr, dict) else {"text": mr}).items()}
                for mr in phase_output.get("memory_reads", [])
            ],
            "prior_phases": {},
        }

        # Extract assessed severity for P3-L0 severity jump detection (AP-9 fix)
        assessed_sev = phase_output.get("assessed_severity",
            phase_output.get("severity", ""))
        if assessed_sev:
            handoff["assessed_severity"] = assessed_sev

        if injection_count > 0:
            handoff["_sanitized"] = True
            handoff["_injection_count"] = injection_count

        # Include sanitized summaries from all prior phases
        for phase, data in incident_context.get("phases", {}).items():
            if isinstance(data, dict):
                prior_summary = data.get("summary", "")
                prior_summary, c = _sanitize_text(prior_summary)
                injection_count += c
                handoff["prior_phases"][phase] = prior_summary

        if self.logger:
            self.logger.log_agent_handoff(
                from_agent=f"{source_phase}_agent",
                to_agent=f"{target_phase}_agent",
                phase_from=source_phase,
                phase_to=target_phase,
                content=handoff,
            )

        return handoff

    def get_handoff_summary(self, handoff: dict) -> str:
        """Return a concise text summary for logging."""
        src = handoff.get("source_phase", "?")
        tgt = handoff.get("target_phase", "?")
        summary = handoff.get("phase_summary", "no summary")
        n_tools = len(handoff.get("tool_results", []))
        return f"[{src} -> {tgt}] {summary} ({n_tools} tool results)"
