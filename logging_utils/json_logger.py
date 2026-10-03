"""
Structured JSON Logger for DEFER Experiments

Middleware for instrumenting all inter-component calls:
  agent -> tool, agent -> memory, agent <-> agent, consensus validation,
  tool response -> agent, memory read/write.

Every event is a single JSON line written to a .jsonl file.
Eval E (consensus overhead) is extracted entirely from these logs.

Usage:
    from logging_utils import ExperimentLogger

    logger = ExperimentLogger(
        eval_name="cyberops_eval_attacks_A",
        config="agenticcyops",
        model="Qwen3-235B-A22B-Instruct-2507",
    )

    # Log a tool call
    with logger.track("monitor_agent", "T8_iam_pam", "tool_call") as event:
        result = call_tool(...)
        event.set_auth("deny", "P2_capability_scoping")
        event.set_interception(step=2)
        event.set_tokens(prompt=1200, completion=647)

    # Or log manually
    logger.log(
        source="admin_agent",
        destination="firewall_api",
        action="tool_call",
        auth_decision="allow",
        mechanism="P2_capability_scoping",
        tokens_used=1847,
        extra={"rule_id": "FW-042"},
    )

    # Set trial context for batch runs
    logger.set_trial("ap1", variant=3, trial=12)
"""

import json
import hashlib
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import BASE_DIR, LOGS_DIR, model_display_name
from .run_metadata import HEADER_FIELDS, build_run_header


_ROOT = str(BASE_DIR)


def _relative(line: str) -> str:
    """Write paths inside this checkout as repo-relative ("./...") so no log
    carries the absolute path of the machine that ran it (e.g. the
    changed_files of a config-integrity event)."""
    return line.replace(_ROOT + "/", "./").replace(_ROOT, ".")


class EventBuilder:
    """Builder for a single log event, used with ExperimentLogger.track() context manager."""

    def __init__(self):
        self.auth_decision: Optional[str] = None
        self.mechanism: Optional[str] = None
        self.interception_step: Optional[int] = None
        self.tokens_prompt: int = 0
        self.tokens_completion: int = 0
        self.payload: Optional[str] = None
        self.extra: dict = {}

    def set_auth(self, decision: str, mechanism: Optional[str] = None):
        """Set authorization decision and the principle that made it.

        Args:
            decision: "allow", "deny", or "escalate"
            mechanism: Which principle blocked/allowed, e.g. "P1_authorized_interface",
                       "P2_capability_scoping", "P3_verified_execution",
                       "P4_memory_integrity", "P5_access_control"
        """
        self.auth_decision = decision
        self.mechanism = mechanism

    def set_interception(self, step: int):
        """Set at which step in the attack chain this was intercepted (1-4, or None)."""
        self.interception_step = step

    def set_tokens(self, prompt: int = 0, completion: int = 0):
        """Set token usage for this call."""
        self.tokens_prompt = prompt
        self.tokens_completion = completion

    def set_payload(self, payload: Any):
        """Set the payload (will be hashed, not stored raw)."""
        if isinstance(payload, str):
            self.payload = payload
        else:
            self.payload = json.dumps(payload, default=str)

    def set_extra(self, **kwargs):
        """Set additional fields to include in the log entry."""
        self.extra.update(kwargs)


class ExperimentLogger:
    """Structured JSON logger for experiment instrumentation.

    Writes one JSON object per line to a .jsonl file. All inter-component
    calls flow through this logger for full auditability.
    """

    def __init__(
        self,
        eval_name: str = "cyberops_eval_attacks_A",
        domain: str = "cyberops",
        config: str = "agenticcyops",
        model: str = "Qwen3-235B-A22B-Instruct-2507",
        logs_dir: Optional[str] = None,
        header: Optional[dict] = None,
    ):
        """
        Args:
            eval_name: Evaluation identifier, typically
                       "{domain}_eval_attacks_{group}" for attack runs or
                       "{domain}_baseline_{group}" for benign runs.
                       Determines the subdirectory under logs/.
            domain: Domain identifier ("cyberops", "healthcare", "finance", "legal").
            config: System configuration ("flat", "acl_hardened", "agenticcyops").
            model: Primary model used for this run.  Host paths are stripped;
                   only the ``<org>/<name>`` part or an API model id is kept.
            logs_dir: Override base logs directory. Defaults to project logs/.
            header: Run metadata written as the first line of the file (see
                    :func:`logging_utils.run_metadata.build_run_header`).
                    When omitted a header with git state and the model is
                    still written, so every log starts with a ``run_header``.
        """
        self.config = config
        self.domain = domain
        self.model = model_display_name(model)
        self.eval_name = eval_name
        self.header: dict = {}

        self._trial_id: Optional[str] = None
        self._ap: Optional[str] = None
        self._variant: Optional[int] = None
        self._trial_num: Optional[int] = None
        self._canaries: list[str] = []

        base = Path(logs_dir) if logs_dir else LOGS_DIR
        self._log_dir = base / eval_name
        self._log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_file = self._log_dir / f"{config}_{timestamp}.jsonl"
        self._file_handle = open(self._log_file, "a", buffering=1)  # line-buffered
        self._write_header(header)

    # ------------------------------------------------------------------ #
    #  Run header
    # ------------------------------------------------------------------ #

    def _write_header(self, header: Optional[dict]):
        """Write the ``run_header`` event as the first line of the file.

        Unlike ordinary events, ``None`` values are kept so the schema is
        visible even when a field is not known yet.
        """
        if header is None:
            header = build_run_header(config=self.config, domain=self.domain,
                                      primary_model=self.model, probe=False)
        else:
            header = dict(header)
            header.setdefault("config", self.config)
            header.setdefault("domain", self.domain)
            if not header.get("primary_model"):
                header["primary_model"] = self.model
        header["primary_model"] = model_display_name(header.get("primary_model"))
        self.header = header
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "eval": self.eval_name,
            "action": "run_header",
            "source": "harness",
            "destination": "log",
        }
        for k in HEADER_FIELDS:
            entry[k] = header.get(k)
        for k, v in header.items():
            entry.setdefault(k, v)
        self._file_handle.write(_relative(json.dumps(entry, default=str)) + "\n")

    def update_header(self, **fields):
        """Record header fields learned after the file was opened (e.g. the
        served model id) as a ``run_header_update`` event."""
        self.header.update(fields)
        if "primary_model" in fields:
            fields["primary_model"] = model_display_name(fields["primary_model"])
        self.log(source="harness", destination="log", action="run_header_update", extra=fields)

    def close(self):
        """Flush and close the log file."""
        if self._file_handle and not self._file_handle.closed:
            self._file_handle.flush()
            self._file_handle.close()

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def log_file(self) -> Path:
        """Path to the current log file."""
        return self._log_file

    # ------------------------------------------------------------------ #
    #  Trial context
    # ------------------------------------------------------------------ #

    def set_trial(self, ap: str, variant: int, trial: int):
        """Set the current trial context. Updates trial_id automatically.

        Args:
            ap: Attack path identifier, e.g. "ap1", "ap2", "benign"
            variant: Variant number (1-5)
            trial: Trial number within this variant
        """
        self._ap = ap
        self._variant = variant
        self._trial_num = trial
        self._trial_id = f"{self.domain}_{ap}_v{variant}_t{trial}_{self.config}"

    def set_trial_id(self, trial_id: str):
        """Set trial_id directly for custom naming."""
        self._trial_id = trial_id

    def set_canaries(self, canaries: Optional[list[str]]):
        """Canary strings of the current trial.

        Any event whose ``extra`` fields or payload text contain one of them
        gets a ``canary_hits`` list; the text itself is never written.  The
        effect oracle uses the hits to decide whether planted content
        reached an outbound action (``mem_read_leak`` / ``exfil`` effects).
        """
        self._canaries = [str(c) for c in (canaries or []) if c]

    def _canary_hits(self, *texts) -> list[str]:
        if not self._canaries:
            return []
        hits = []
        for t in texts:
            if not t:
                continue
            if not isinstance(t, str):
                t = json.dumps(t, default=str)
            for c in self._canaries:
                if c in t and c not in hits:
                    hits.append(c)
        return hits

    # ------------------------------------------------------------------ #
    #  Core logging
    # ------------------------------------------------------------------ #

    def log(
        self,
        source: str,
        destination: str,
        action: str,
        auth_decision: Optional[str] = None,
        mechanism: Optional[str] = None,
        interception_step: Optional[int] = None,
        latency_ms: Optional[float] = None,
        tokens_used: Optional[int] = None,
        tokens_prompt: Optional[int] = None,
        tokens_completion: Optional[int] = None,
        payload_hash: Optional[str] = None,
        extra: Optional[dict] = None,
        scan_text: Optional[Any] = None,
    ):
        """Write a single structured log entry.

        Args:
            source: Originator ("monitor_agent", "host", "consensus_validator", etc.)
            destination: Target ("T8_iam_pam", "M3_policy_store", "admin_agent", etc.)
            action: What happened ("tool_call", "memory_read", "memory_write",
                    "agent_handoff", "consensus_vote", "escalation", "tool_response")
            auth_decision: "allow", "deny", or "escalate"
            mechanism: Defensive principle ("P1_authorized_interface",
                       "P2_capability_scoping", "P3_verified_execution",
                       "P4_memory_integrity", "P5_access_control")
            interception_step: Step where attack was blocked (1-4), or None
            latency_ms: Time taken for this call in milliseconds
            tokens_used: Total tokens (shorthand for prompt + completion)
            tokens_prompt: Prompt/input tokens
            tokens_completion: Completion/output tokens
            payload_hash: Hash of the payload (computed automatically if not provided)
            extra: Additional fields to include
            scan_text: Content that is scanned for the trial's canary strings
                       but never written (see :meth:`set_canaries`)
        """
        total_tokens = tokens_used
        if total_tokens is None and (tokens_prompt or tokens_completion):
            total_tokens = (tokens_prompt or 0) + (tokens_completion or 0)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trial_id": self._trial_id,
            "eval": self.eval_name,
            "domain": self.domain,
            "config": self.config,
            "model": self.model,
            "source": source,
            "destination": destination,
            "action": action,
            "payload_hash": payload_hash,
            "auth_decision": auth_decision,
            "mechanism": mechanism,
            "interception_step": interception_step,
            "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
            "tokens_used": total_tokens,
            "tokens_prompt": tokens_prompt,
            "tokens_completion": tokens_completion,
        }

        if self._ap:
            entry["ap"] = self._ap
        if self._variant is not None:
            entry["variant"] = self._variant
        if self._trial_num is not None:
            entry["trial"] = self._trial_num

        if extra:
            entry.update(extra)
        if entry.get("model"):
            entry["model"] = model_display_name(entry["model"])
        hits = self._canary_hits(extra, scan_text)
        if hits:
            entry["canary_hits"] = hits

        # Remove None values for cleaner logs
        entry = {k: v for k, v in entry.items() if v is not None}

        line = _relative(json.dumps(entry, default=str))
        self._file_handle.write(line + "\n")

    # ------------------------------------------------------------------ #
    #  Context manager for automatic latency tracking
    # ------------------------------------------------------------------ #

    @contextmanager
    def track(self, source: str, destination: str, action: str):
        """Context manager that automatically measures latency and logs the event.

        Usage:
            with logger.track("monitor_agent", "T1_ueba", "tool_call") as event:
                result = call_tool(...)
                event.set_auth("allow")
                event.set_tokens(prompt=500, completion=200)
                event.set_payload(result)

        Latency is measured from entry to exit of the context manager.
        """
        event = EventBuilder()
        start = time.perf_counter()

        yield event

        elapsed_ms = (time.perf_counter() - start) * 1000

        payload_hash = None
        if event.payload:
            payload_hash = hashlib.sha256(event.payload.encode()).hexdigest()[:8]

        self.log(
            source=source,
            destination=destination,
            action=action,
            auth_decision=event.auth_decision,
            mechanism=event.mechanism,
            interception_step=event.interception_step,
            latency_ms=elapsed_ms,
            tokens_prompt=event.tokens_prompt,
            tokens_completion=event.tokens_completion,
            payload_hash=payload_hash,
            extra=event.extra if event.extra else None,
        )

    # ------------------------------------------------------------------ #
    #  Convenience methods for common event types
    # ------------------------------------------------------------------ #

    def log_tool_call(
        self,
        agent: str,
        tool: str,
        auth_decision: str = "allow",
        mechanism: Optional[str] = None,
        latency_ms: Optional[float] = None,
        tokens_prompt: int = 0,
        tokens_completion: int = 0,
        payload: Optional[Any] = None,
        interception_step: Optional[int] = None,
        extra: Optional[dict] = None,
    ):
        """Log an agent -> tool call.

        ``extra`` may carry a compact ``arguments`` snapshot of the call so
        that the attack evaluator can match scripted adversarial actions on
        (tool, operation, parameters) instead of tool name alone.
        """
        payload_hash = None
        raw = None
        if payload:
            raw = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
            payload_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]

        self.log(
            source=agent,
            destination=tool,
            action="tool_call",
            auth_decision=auth_decision,
            mechanism=mechanism,
            latency_ms=latency_ms,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            payload_hash=payload_hash,
            interception_step=interception_step,
            extra=extra,
            scan_text=raw,
        )

    def log_memory_read(
        self,
        agent: str,
        store: str,
        auth_decision: str = "allow",
        mechanism: Optional[str] = None,
        latency_ms: Optional[float] = None,
        num_results: Optional[int] = None,
        extra: Optional[dict] = None,
    ):
        """Log an agent -> memory store read."""
        fields = dict(extra or {})
        if num_results is not None:
            fields["num_results"] = num_results
        self.log(
            source=agent,
            destination=store,
            action="memory_read",
            auth_decision=auth_decision,
            mechanism=mechanism,
            latency_ms=latency_ms,
            extra=fields or None,
        )

    def log_memory_write(
        self,
        agent: str,
        store: str,
        auth_decision: str = "allow",
        mechanism: Optional[str] = None,
        latency_ms: Optional[float] = None,
        payload: Optional[Any] = None,
        cosine_similarity: Optional[float] = None,
        extra: Optional[dict] = None,
    ):
        """Log an agent -> memory store write (goes through P4 write-boundary filtering)."""
        payload_hash = None
        raw = None
        if payload:
            raw = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
            payload_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]

        extra = dict(extra or {})
        if cosine_similarity is not None:
            extra["cosine_similarity"] = round(cosine_similarity, 4)

        self.log(
            source=agent,
            destination=store,
            action="memory_write",
            auth_decision=auth_decision,
            mechanism=mechanism,
            latency_ms=latency_ms,
            payload_hash=payload_hash,
            extra=extra or None,
            scan_text=raw,
        )

    def log_consensus_vote(
        self,
        validator: str,
        proposal_source: str,
        vote: str,
        confidence: Optional[float] = None,
        latency_ms: Optional[float] = None,
        tokens_prompt: int = 0,
        tokens_completion: int = 0,
        reasoning: Optional[str] = None,
    ):
        """Log a single validator's consensus vote.

        Args:
            validator: Validator name ("qwen3_32b", "deepseek_r1", "claude_sonnet")
            proposal_source: Who proposed the action ("admin_agent")
            vote: "approve", "reject", or "abstain"
            confidence: Validator's confidence score (0-1)
        """
        extra = {}
        if confidence is not None:
            extra["confidence"] = round(confidence, 4)
        if reasoning:
            extra["reasoning_hash"] = hashlib.sha256(reasoning.encode()).hexdigest()[:8]

        self.log(
            source=validator,
            destination=proposal_source,
            action="consensus_vote",
            auth_decision=vote,
            mechanism="P3_verified_execution",
            latency_ms=latency_ms,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            extra=extra or None,
        )

    def log_consensus_result(
        self,
        validators: list[str],
        votes: list[str],
        result: str,
        total_latency_ms: Optional[float] = None,
    ):
        """Log the aggregate consensus decision.

        Args:
            validators: List of validator names used
            votes: Corresponding list of votes ("approve"/"reject")
            result: Final decision ("approved", "rejected", "escalated")
        """
        approvals = sum(1 for v in votes if v == "approve")
        self.log(
            source="consensus_module",
            destination="host",
            action="consensus_result",
            auth_decision=result,
            mechanism="P3_verified_execution",
            latency_ms=total_latency_ms,
            extra={
                "validators": validators,
                "votes": votes,
                "approvals": approvals,
                "threshold": len(validators),
                "quorum": f"{approvals}/{len(validators)}",
            },
        )

    def log_escalation(
        self,
        source: str,
        reason: str,
        severity: Optional[str] = None,
    ):
        """Log a human-in-the-loop escalation (P3 Recovery Loop)."""
        self.log(
            source=source,
            destination="human_analyst",
            action="escalation",
            auth_decision="escalate",
            mechanism="P3_verified_execution",
            extra={
                "reason": reason,
                "severity": severity,
            },
        )

    def log_agent_handoff(
        self,
        from_agent: str,
        to_agent: str,
        phase_from: Optional[str] = None,
        phase_to: Optional[str] = None,
        latency_ms: Optional[float] = None,
        content: Optional[Any] = None,
    ):
        """Log a Host-mediated phase handoff (Monitor -> Analyze -> Admin -> Report).

        ``content`` (the handoff payload) is scanned for canaries only.
        """
        extra = {}
        if phase_from:
            extra["phase_from"] = phase_from
        if phase_to:
            extra["phase_to"] = phase_to

        self.log(
            source=from_agent,
            destination=to_agent,
            action="agent_handoff",
            latency_ms=latency_ms,
            extra=extra or None,
            scan_text=content,
        )


# ------------------------------------------------------------------ #
#  Module-level convenience function
# ------------------------------------------------------------------ #

_default_logger: Optional[ExperimentLogger] = None


def log_event(**kwargs):
    """Log using the module-level default logger. Call init_logger() first."""
    global _default_logger
    if _default_logger is None:
        raise RuntimeError("Call logging_utils.init_logger() before log_event()")
    _default_logger.log(**kwargs)


def init_logger(eval_name: str, domain: str, config: str, model: str, **kwargs) -> ExperimentLogger:
    """Initialize and return the module-level default logger."""
    global _default_logger
    _default_logger = ExperimentLogger(eval_name=eval_name, domain=domain, config=config, model=model, **kwargs)
    return _default_logger
