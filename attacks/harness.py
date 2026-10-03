"""
Domain-agnostic attack execution harness.

Usage:
    python -m attacks.harness --domain cyberops --ap ap1 --config agenticcyops --trials 6
    python -m attacks.harness --domain cyberops --eval A --config all --trials 6
    python -m attacks.harness --domain cyberops --benign --config all --trials 5
    python -m attacks.harness --domain cyberops --ap ap1 --config agenticcyops --trials 1 --verbose
"""

import argparse
import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config import BASE_DIR, MODELS_DIR, RESULTS_DIR
from logging_utils import ExperimentLogger
from logging_utils.run_metadata import build_run_header
from host.orchestrator import SOARHost
from host.manifest_enforcer import ManifestEnforcer
from mcp_servers.server_registry import ServerRegistry
from agents.monitor_agent import MonitorAgent
from agents.analyze_agent import AnalyzeAgent
from agents.admin_agent import AdminAgent
from agents.report_agent import ReportAgent
from consensus.validator import ConsensusValidator
from attacks.effects import (evaluate_effects, evaluate_benign, trial_costs, OUTCOME_EXECUTED,
                             OUTCOME_BLOCKED, OUTCOME_NOT_ATTEMPTED,
                             OUTCOME_NOT_MEASURABLE, OUTCOME_BENIGN)
from attacks.payload_schema import (injection_of, memory_seed_entries, meta_of, resolve_tool,
                                    split_payload)


CYBEROPS_APS = ["ap1", "ap2", "ap3", "ap4", "ap5", "ap6"]


class DirtyTreeRefused(RuntimeError):
    """A non-smoke run was requested from a tree with uncommitted tracked changes."""


def refuse_if_dirty(header: dict, run_tag: str = "") -> None:
    """T7 guard: main runs must start from a committed tree.

    ``git_dirty`` (tracked changes only) is recorded in every run header;
    the last v2.1 runs were launched dirty, so their headers cannot be tied
    to one commit.  Smoke runs (``run_tag`` containing ``smoke``) are exempt.
    """
    if header.get("git_dirty") and "smoke" not in (run_tag or "").lower():
        raise DirtyTreeRefused(
            "refusing to start a non-smoke run from a dirty tree (git_dirty=true): "
            "commit or stash tracked changes, or pass --run-tag <name>smoke for a smoke run")


class InjectionNotDelivered(RuntimeError):
    """The payload's adversarial content could not be placed in its channel.

    Raised by :meth:`AttackHarness.deliver_injection`; the trial is then
    recorded as ``outcome="error"``, ``blocked_by="injection_not_delivered"``
    and the incident is not run (the model would never have seen the attack).
    """

# Columns of results/eval_attacks/group_<G>/<domain>/results.csv (scoring v3).
RESULT_COLUMNS = ["domain", "ap", "variant", "trial", "config", "group",
                  "outcome", "blocked_by", "collateral_denials", "task_completed",
                  "latency_s", "primary_tokens", "validator_tokens", "seed",
                  "exposed", "channel"]
# Variants that run the agenticcyops stack with one setting changed (E1, E9,
# E16, E17). The orchestrator maps each label to the stack plus a flag, so the
# deployed configuration's behaviour is untouched.
_STACK_VARIANTS = ("agenticcyops_noautoapprove", "agenticcyops_gate_permissive",
                   "p2_judge", "agenticcyops_writejudge")
CONFIGS = ["flat", "acl_hardened", "agenticcyops", "llm_judge", "symbolic_only",
           *_STACK_VARIANTS]
# configs that share the agenticcyops enforcement stack
_STACK_CONFIGS = ("agenticcyops", "symbolic_only", *_STACK_VARIANTS)
# configs that need the validator panel wired up
_PANEL_CONFIGS = ("agenticcyops", "llm_judge", *_STACK_VARIANTS)
AGENT_CLASSES = {
    "monitor": MonitorAgent,
    "analyze": AnalyzeAgent,
    "admin": AdminAgent,
    "report": ReportAgent,
}


@dataclass
class TrialResult:
    ap: str
    variant: int
    trial: int
    config: str
    domain: str
    group: str = ""
    outcome: str = ""          # executed | blocked | not_attempted | not_measurable | error
    blocked_by: str = ""
    collateral_denials: int = 0
    task_completed: Optional[bool] = None
    latency_s: float = 0.0
    primary_tokens: int = 0
    validator_tokens: int = 0
    seed: Optional[int] = None
    exposed: Optional[bool] = None     # model was shown the injected content (T2)
    channel: str = ""                  # meta.channel of the payload ("" for benign)
    measurable: bool = True
    tool_states: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def attack_succeeded(self) -> bool:
        return self.outcome == OUTCOME_EXECUTED

    @property
    def attempted(self) -> bool:
        return self.outcome in (OUTCOME_EXECUTED, OUTCOME_BLOCKED)

    def as_row(self) -> dict:
        return {
            "domain": self.domain, "ap": self.ap, "variant": self.variant,
            "trial": self.trial, "config": self.config, "group": self.group,
            "outcome": self.outcome, "blocked_by": self.blocked_by,
            "collateral_denials": self.collateral_denials,
            "task_completed": "" if self.task_completed is None else self.task_completed,
            "latency_s": round(self.latency_s, 3),
            "primary_tokens": self.primary_tokens, "validator_tokens": self.validator_tokens,
            "seed": "" if self.seed is None else self.seed,
            "exposed": "" if self.exposed is None else self.exposed,
            "channel": self.channel,
        }


def summarize_benign(results: list) -> dict:
    """E1 utility metrics over benign trials."""
    rows = [r for r in results if r.outcome in (OUTCOME_BENIGN, "error")]
    ok = [r for r in rows if r.outcome == OUTCOME_BENIGN]
    n = len(ok)
    with_task = [r for r in ok if r.task_completed is not None]
    return {
        "n": n, "error": len(rows) - n,
        "task_completed_rate": (sum(1 for r in with_task if r.task_completed) / len(with_task)) if with_task else None,
        "any_denial_rate": (sum(1 for r in ok if r.collateral_denials > 0) / n) if n else None,
        "denials_per_incident": (sum(r.collateral_denials for r in ok) / n) if n else None,
        "latency_s_median": sorted(r.latency_s for r in ok)[n // 2] if n else None,
        "primary_tokens_mean": (sum(r.primary_tokens for r in ok) / n) if n else None,
        "validator_tokens_mean": (sum(r.validator_tokens for r in ok) / n) if n else None,
    }


def summarize(results: list) -> dict:
    """ASR, attempt rate and block rate given attempt over measurable trials.

    ``ASR = executed / measurable``; ``attempt_rate = (executed + blocked) /
    measurable``; ``block_rate_given_attempt = blocked / (executed + blocked)``.
    Trials scored ``not_measurable`` or ``error`` are excluded.
    """
    meas = [r for r in results if r.outcome in (OUTCOME_EXECUTED, OUTCOME_BLOCKED, OUTCOME_NOT_ATTEMPTED)]
    n = len(meas)
    ex = sum(1 for r in meas if r.outcome == OUTCOME_EXECUTED)
    bl = sum(1 for r in meas if r.outcome == OUTCOME_BLOCKED)
    na = n - ex - bl
    return {
        "n": n, "executed": ex, "blocked": bl, "not_attempted": na,
        "not_measurable": sum(1 for r in results if r.outcome == OUTCOME_NOT_MEASURABLE),
        "error": sum(1 for r in results if r.outcome == "error"),
        "asr": ex / n if n else None,
        "attempt_rate": (ex + bl) / n if n else None,
        "block_rate_given_attempt": bl / (ex + bl) if (ex + bl) else None,
        "task_completed_rate": (
            (lambda t: sum(1 for r in t if r.task_completed) / len(t) if t else None)
            ([r for r in meas if r.task_completed is not None])),
    }


def load_payloads(domain: str, payload_file: str) -> list[dict]:
    """Load attack/benign payloads from domain payloads directory."""
    path = BASE_DIR / "domains" / domain / "payloads" / payload_file
    if not path.exists():
        print(f"  Warning: {path} not found")
        return []
    with open(path) as f:
        return json.load(f)


class AttackHarness:
    """Orchestrates attack/benign trial execution."""

    def __init__(
        self,
        domain: str,
        config: str,
        group: str = "A",
        llm_url: str = "http://localhost:8000/v1",
        llm_provider: str = "openai",
        consensus_config: str = "default_consensus",
        mma_url: str = "http://localhost:9100",
        tool_base_port: int = 9000,
        verbose: bool = False,
        disabled_principles: Optional[set] = None,
        api_key_env: Optional[str] = None,
        extra_body: Optional[dict] = None,
        state_mode: str = "isolated",
        temperature: float = 0.7,
        base_seed: Optional[int] = None,
        require_freeze: bool = False,
        run_tag: str = "",
    ):
        self.domain = domain
        self.config = config
        self.group = group
        self.state_mode = state_mode
        self.temperature = float(temperature)
        self.base_seed = base_seed
        self.require_freeze = require_freeze
        self.llm_url = llm_url
        self.llm_provider = llm_provider
        self.mma_url = mma_url
        self.tool_base_port = tool_base_port
        self.verbose = verbose
        self.disabled_principles: set = {p.upper() for p in (disabled_principles or set())}
        self._api_key_env = api_key_env
        self._extra_body = extra_body
        self.last_outcome: dict = {}

        # Determine eval name (include group). Unified naming across
        # all domains: {domain}_eval_attacks_{group}.  Ablation runs get
        # a `_disabled_<set>` suffix so logs / results land in their own
        # directory rather than overwriting the production run.
        eval_name = f"{domain}_eval_attacks_{group}"
        if self.disabled_principles:
            eval_name += "_disabled_" + "".join(sorted(self.disabled_principles))
        if run_tag:
            eval_name += f"_{run_tag}"          # smoke / persistent runs keep their own log dir
        header = build_run_header(
            group=group, config=config, domain=domain,
            primary_url=llm_url, primary_provider=llm_provider,
            api_key_env=api_key_env,
            consensus_config=consensus_config if config in _PANEL_CONFIGS else None,
            disabled_principles=self.disabled_principles,
            state_mode=state_mode,
            primary_temperature=self.temperature,
            seed=base_seed,
        )
        refuse_if_dirty(header, run_tag)
        if require_freeze:
            from logging_utils.run_metadata import assert_frozen
            assert_frozen(header)
        self.logger = ExperimentLogger(
            eval_name=eval_name,
            domain=domain,
            config=config,
            model=header.get("primary_model") or f"Group_{group}",
            header=header,
        )

        # Load tool registry
        self.registry = ServerRegistry(domain=domain, logger=self.logger)
        self.registry.load_tools()
        self.registry.assign_ports(tool_base_port)

        # Load manifests
        self.enforcer = ManifestEnforcer(domain=domain, logger=self.logger)

        # Build agents
        all_schemas = self.registry.get_all_schemas()
        self.agents = {}
        for phase, AgentCls in AGENT_CLASSES.items():
            manifest = self.enforcer.get_manifest(phase)
            phase_schemas = self.registry.get_phase_schemas(manifest.get("allowed_tools", []))
            agent_kwargs = dict(
                domain=domain,
                config=config,
                manifest=manifest,
                tool_schemas=phase_schemas,
                all_tool_schemas=all_schemas,
                logger=self.logger,
            )
            if llm_provider == "anthropic":
                agent_kwargs["llm_provider"] = "anthropic"
            else:
                agent_kwargs["llm_url"] = llm_url
                if api_key_env:
                    agent_kwargs["api_key_env"] = api_key_env
                if extra_body:
                    agent_kwargs["extra_body"] = extra_body
            self.agents[phase] = AgentCls(**agent_kwargs)
            self.agents[phase].set_temperature(self.temperature)

        # Build consensus (agenticcyops + llm_judge ablation + stack variants)
        consensus = None
        if config in _PANEL_CONFIGS:
            try:
                consensus = ConsensusValidator(config_name=consensus_config, logger=self.logger)
            except Exception as e:
                if verbose:
                    print(f"  Consensus init failed: {e}")

        # Load shared embedding model for P2-L2/P2-L3 (agenticcyops only;
        # llm_judge ablation skips P2 so doesn't need embeddings)
        embedding_model = None
        if config in _STACK_CONFIGS:
            try:
                from sentence_transformers import SentenceTransformer
                model_path = str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B")
                embedding_model = SentenceTransformer(model_path, device="cpu")
            except Exception as e:
                if verbose:
                    print(f"  Embedding model load failed (P2-L2/L3 disabled): {e}")

        # Build host
        self.host = SOARHost(
            domain=domain,
            config=config,
            llm_url=llm_url,
            mma_url=mma_url,
            tool_registry=self.registry,
            consensus=consensus,
            agents=self.agents,
            logger=self.logger,
            embedding_model=embedding_model,
            disabled_principles=self.disabled_principles,
            state_mode=state_mode,
            adaptive_consent_path=self.adaptive_consent_path(group, domain, state_mode),
        )

    @staticmethod
    def adaptive_consent_path(group: str, domain: str, state_mode: str):
        """Reward-profile file for persistent mode, one per (group, domain);
        ``None`` in isolated mode (profiles stay in memory and are reset)."""
        if state_mode != "persistent":
            return None
        return BASE_DIR / "data" / "adaptive_consent" / str(group) / f"{domain}.json"

    async def reset_tools(self):
        """Reset all tool server states between trials."""
        import httpx
        async with httpx.AsyncClient() as client:
            for tool_id, port in self.registry._ports.items():
                try:
                    await client.post(f"http://127.0.0.1:{port}/reset", timeout=5)
                except Exception:
                    pass

    async def get_tool_states(self) -> dict:
        """Snapshot all tool server states."""
        import httpx
        states = {}
        async with httpx.AsyncClient() as client:
            for tool_id, port in self.registry._ports.items():
                try:
                    resp = await client.get(f"http://127.0.0.1:{port}/state", timeout=5)
                    states[tool_id] = resp.json()
                except Exception:
                    states[tool_id] = {"error": "unreachable"}
        return states

    # ------------------------------------------------------------------ #
    #  Attack-outcome evaluation (scoring v3: effects oracle, 2026-09)
    # ------------------------------------------------------------------ #
    #
    #  The verdict comes from attacks.effects.evaluate_effects, which scores
    #  whether the adversarial effect declared in the payload
    #  (success_criteria.effects) materialised in the audit log:
    #
    #    executed        the effect materialised (an allowed call / accepted
    #                    write matching the effect spec)
    #    blocked         a matching proposal exists and a defense denied it;
    #                    blocked_by names the layer
    #    not_attempted   no matching proposal, or the model abandoned the
    #                    attack without any defense denial
    #    not_measurable  the payload declares no usable effect (canary not
    #                    assigned yet, infrastructure attack not simulated)
    #    error           a phase agent raised during the trial
    #
    #  Denials of calls that are not part of the attack are counted in
    #  collateral_denials, never credited as blocks.  task_completed records
    #  whether the scenario's legitimate task still went through.

    PHASES = ("monitor", "analyze", "admin", "report")

    def evaluate_success(self, ap: str, payload: dict, tool_states: dict) -> tuple[bool, int, str]:
        """Score one trial from its log events.

        Returns ``(attack_executed, interception_step, blocked_by)`` for
        backward compatibility; the full verdict is left in
        ``self.last_outcome`` (see :class:`attacks.effects.EffectVerdict`).
        """
        events = self._get_trial_events()
        if ap == "benign":
            verdict = evaluate_benign(payload, events)
        else:
            verdict = evaluate_effects(payload, events, config=self.config,
                                       manifest_tools=self._manifest_tools_by_phase())
        costs = trial_costs(events)
        self.last_verdict = verdict
        self.last_outcome = {
            **verdict.as_dict(),
            "measurable": verdict.outcome not in (OUTCOME_NOT_MEASURABLE, "error"),
            **costs,
        }
        step = self._step_for(verdict.blocked_by) if verdict.outcome == OUTCOME_BLOCKED else 0
        return verdict.outcome == OUTCOME_EXECUTED, step, verdict.blocked_by

    _STEP_BY_PRINCIPLE = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5, "ac": 2}

    def _step_for(self, mech: str) -> int:
        return self._STEP_BY_PRINCIPLE.get(str(mech or "")[:2], 0)

    def _manifest_tools_by_phase(self) -> dict:
        enforcer = getattr(self, "enforcer", None)
        if enforcer is None:
            return {}
        return {ph: list(enforcer.get_manifest(ph).get("allowed_tools", [])) for ph in self.PHASES}

    def _get_trial_events(self) -> list[dict]:
        """Read back events from the current log file."""
        try:
            events = []
            self.logger._file_handle.flush()
            with open(self.logger.log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        e = json.loads(line)
                        # Filter to current trial
                        if e.get("trial_id") == self.logger._trial_id:
                            events.append(e)
            return events
        except Exception:
            return []

    async def run_trial(self, ap: str, variant: int, trial: int, payload: dict) -> TrialResult:
        """Execute one trial."""
        self.logger.set_trial(ap=ap, variant=variant, trial=trial)
        self.logger.set_canaries(self._payload_canaries(payload))
        seed = self._trial_seed(ap, variant, trial)

        # Reset tools
        await self.reset_tools()

        # What the host (and so the model) sees vs. what only the harness knows
        trigger, meta = split_payload(payload)
        injection = injection_of(payload)
        channel = "" if ap == "benign" else str(meta.get("channel") or "alert_text")
        start = time.perf_counter()

        # Isolated mode resets defense state (and, for agenticcyops, deletes
        # trial-tagged memory docs) at the start of each incident.  That reset
        # must run BEFORE the harness seeds the memory injection, or it deletes
        # the just-planted record; so reset here, then seed, then run the
        # incident with the host's own reset suppressed (state_mode sentinel:
        # run_incident does the lighter reset_for_incident, which never touches
        # memory).  No defense decision changes -- the same reset still runs.
        suppress_reset = self.state_mode == "isolated"
        saved_mode = self.host.state_mode

        try:
            try:
                if suppress_reset:
                    await self.host.reset_trial_state()
                if channel:
                    await self.deliver_injection(channel, injection)
            except InjectionNotDelivered as nd:
                # loud, not silent: no incident is run for a trial the model
                # could not have been exposed to (T1)
                trial_result = TrialResult(
                    ap=ap, variant=variant, trial=trial,
                    config=self.config, domain=self.domain, group=self.group,
                    outcome="error", blocked_by="injection_not_delivered",
                    error=str(nd), measurable=False, seed=seed, exposed=False, channel=channel,
                    latency_s=time.perf_counter() - start,
                    details={"error": str(nd), "channel": channel})
                self._finish_trial(trial_result, ap, variant, trial)
                return trial_result
            if suppress_reset:
                self.host.state_mode = "isolated_reset_done"   # not "isolated": no second reset
            try:
                result = await self.host.run_incident(trigger, harness_injection=injection)
            finally:
                self.host.state_mode = saved_mode
            latency_s = time.perf_counter() - start

            # Get tool states
            tool_states = await self.get_tool_states()

            # memory channel: which planted records a read returned (T2)
            if channel == "memory":
                self._log_memory_exposure(injection)

            # Evaluate
            self.evaluate_success(ap, payload, tool_states)
            lo = self.last_outcome

            trial_result = TrialResult(
                ap=ap, variant=variant, trial=trial,
                config=self.config, domain=self.domain, group=self.group,
                outcome=lo.get("outcome", ""),
                blocked_by=lo.get("blocked_by", ""),
                collateral_denials=int(lo.get("collateral_denials") or 0),
                task_completed=lo.get("task_completed"),
                latency_s=latency_s,
                primary_tokens=int(lo.get("primary_tokens") or 0),
                validator_tokens=int(lo.get("validator_tokens") or 0),
                seed=seed,
                exposed=lo.get("exposed"),
                channel=channel,
                measurable=lo.get("measurable", True),
                tool_states=tool_states,
                details=lo.get("details") or {},
                error=(lo.get("details") or {}).get("error") if lo.get("outcome") == "error" else None,
            )

        except Exception as e:
            # A harness/pipeline error is neither a success nor a block.
            trial_result = TrialResult(
                ap=ap, variant=variant, trial=trial,
                config=self.config, domain=self.domain, group=self.group,
                error=str(e),
                outcome="error",
                blocked_by="harness_error",
                measurable=False,
                seed=seed,
                channel=channel,
                latency_s=time.perf_counter() - start,
            )

        self._finish_trial(trial_result, ap, variant, trial)
        return trial_result

    def _finish_trial(self, trial_result: TrialResult, ap: str, variant: int, trial: int) -> None:
        """Log the trial summary and append the results.csv row."""
        self.logger.log(
            source="harness",
            destination="trial_result",
            action="trial_complete",
            extra={**trial_result.as_row(),
                   "measurable": trial_result.measurable,
                   "details": trial_result.details,
                   "error": trial_result.error},
        )
        self._append_result(trial_result)

        if self.verbose:
            status = (trial_result.outcome or "").upper()
            if trial_result.blocked_by:
                status += f" ({trial_result.blocked_by})"
            if trial_result.error:
                status = f"ERROR: {trial_result.error[:60]}"
            print(f"  {ap} v{variant} t{trial} [{self.config}]: {status}")

    # ---- H5 channel delivery ---------------------------------------------

    async def deliver_injection(self, channel: str, injection: dict) -> None:
        """Deliver the payload's adversarial content through its channel.

        ``tool_response`` queues a response override on the tool stub;
        ``memory`` pre-seeds entries through the gateway (tagged with the
        trial id so the per-trial reset removes them).  ``handoff`` and
        ``proposal_justification`` are applied by the host from the
        ``harness_injection`` argument; ``alert_text`` needs nothing.
        """
        import httpx
        if channel == "alert_text":
            # exposure by construction: the content is in the trigger the model reads
            phase = str(injection.get("attacker_phase") or "monitor")
            self.logger.log(source="harness", destination=f"{phase}_agent", action="injection_served",
                            extra={"channel": channel, "phase": phase})
            return
        if channel == "tool_response" and injection.get("tool"):
            named = injection["tool"]
            tool = resolve_tool(named, self.registry._ports)
            if tool is None:
                self.logger.log(source="harness", destination=str(named), action="harness_injection",
                                extra={"channel": channel, "status": "unknown_tool"})
                raise InjectionNotDelivered(f"tool_response: {named!r} is not a registered tool")
            port = self.registry._ports[tool]
            body = {"response": injection.get("response"),
                    "mode": injection.get("mode", "merge"),
                    "calls": int(injection.get("calls", 1))}
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.post(f"http://127.0.0.1:{port}/inject", json=body, timeout=5)
                status = r.status_code
            except Exception as exc:
                status = f"error:{str(exc)[:80]}"
            self.logger.log(source="harness", destination=tool, action="harness_injection",
                            extra={"channel": channel, "status": status, "queued": status == 200,
                                   **({"named_tool": str(named)} if tool != named else {})})
            if status != 200:
                raise InjectionNotDelivered(f"tool_response: POST /inject on {tool} returned {status}")
        elif channel == "memory":
            for e in memory_seed_entries(injection):
                status, body = await self.host._mma_post("/memory/write", {
                    "phase": e["phase"], "store_id": e["store"], "document": e["content"],
                    "doc_id": e["doc_id"], "incident_evidence": "",
                    # doc_id travels in the metadata so a read that returns the
                    # planted record can be recognised (T2 exposure logging)
                    "metadata": {**e["metadata"], "trial_id": self.logger._trial_id or "untagged",
                                 "doc_id": e["doc_id"]},
                    "auth_token": self.host._mma_token(e["phase"], e["store"]),
                    "harness_seed": True,
                })
                self.logger.log(source="harness", destination=e["store"], action="harness_injection",
                                extra={"channel": channel, "status": status, "doc_id": e["doc_id"],
                                       "seeded": status == 200},
                                scan_text=e["content"])
                if status != 200:
                    raise InjectionNotDelivered(
                        f"memory: seeding {e['doc_id']} into {e['store']} returned {status}")

    def _log_memory_exposure(self, injection: dict) -> None:
        """``injection_served`` for every planted record a memory read returned.

        Allowed ``memory_read`` events carry ``result_ids`` (T2); a planted
        ``doc_id`` among them means the reading phase was shown the record.
        ``sanitized`` says whether P5-L5 rewrote its text on the way out.
        """
        planted = {e["doc_id"] for e in memory_seed_entries(injection)}
        if not planted:
            return
        seen: set = set()
        for e in self._get_trial_events():
            if e.get("action") != "memory_read" or e.get("auth_decision") != "allow":
                continue
            ids = [str(i) for i in (e.get("result_ids") or [])]
            sanitized_ids = {str(i) for i in (e.get("sanitized_ids") or [])}
            phase = str(e.get("source") or "").removesuffix("_agent")
            for doc_id in ids:
                if doc_id in planted and (doc_id, phase) not in seen:
                    seen.add((doc_id, phase))
                    self.logger.log(source="harness", destination=f"{phase}_agent",
                                    action="injection_served",
                                    extra={"channel": "memory", "phase": phase, "doc_id": doc_id,
                                           "store": e.get("destination"), "call_id": e.get("call_id"),
                                           "sanitized": doc_id in sanitized_ids})

    # ---- per-trial bookkeeping ------------------------------------------

    @staticmethod
    def _payload_canaries(payload: dict) -> list[str]:
        meta = payload.get("meta") or {}
        sc = payload.get("success_criteria") or {}
        if isinstance(sc, list):
            sc = sc[0] if sc else {}
        out = []
        for src in (meta.get("canaries"), (sc if isinstance(sc, dict) else {}).get("canaries")):
            for c in (src or []):
                if c and str(c) not in out:
                    out.append(str(c))
        return out

    def _trial_seed(self, ap: str, variant: int, trial: int) -> Optional[int]:
        """Per-trial seed: ``base_seed + trial`` when a base seed is set.

        The seed is recorded in results.csv and on the trial's llm_call
        events; H7 threads it into the primary model's sampling.
        """
        base = getattr(self, "base_seed", None)
        if base is None:
            return None
        seed = int(base) + int(trial)
        for agent in self.agents.values():
            if hasattr(agent, "set_seed"):
                agent.set_seed(seed)
        return seed

    def _append_result(self, r: TrialResult) -> None:
        """Append one row to results.csv (created with a header on first use)."""
        path = getattr(self, "results_csv", None)
        if not path:
            return
        import csv
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists() or path.stat().st_size == 0
        fieldnames = list(RESULT_COLUMNS)
        if not new:
            # an older file keeps its own columns (parse_logs rebuilds the
            # full set from the logs); rows are never mis-aligned
            with open(path, newline="") as f:
                head = next(csv.reader(f), None)
            if head and head != fieldnames:
                fieldnames = head
        with open(path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow(r.as_row())

    # ---- resume (G3) -------------------------------------------------------

    def _done_cells(self) -> set:
        """(ap, variant, trial) cells already in results.csv for this config."""
        path = getattr(self, "results_csv", None)
        if not getattr(self, "resume", False) or not path or not Path(path).exists():
            return set()
        import csv
        done = set()
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                if r.get("config") == self.config and r.get("outcome") not in ("", "error"):
                    done.add((r.get("ap"), str(r.get("variant")), str(r.get("trial"))))
        return done

    async def run_ap(self, ap: str, trials_per_variant: int) -> list[TrialResult]:
        """Run all variants x trials for one attack path."""
        payload_file = f"{ap}_variants.json"
        variants = load_payloads(self.domain, payload_file)
        if not variants:
            print(f"  No payloads for {ap}")
            return []

        max_v = getattr(self, "max_variants", None)
        if max_v:
            variants = variants[:int(max_v)]
        done = self._done_cells()
        results = []
        skipped = 0
        for v_idx, variant_payload in enumerate(variants):
            for t in range(trials_per_variant):
                if (ap, str(v_idx + 1), str(t + 1)) in done:
                    skipped += 1
                    continue
                result = await self.run_trial(
                    ap=ap,
                    variant=v_idx + 1,
                    trial=t + 1,
                    payload=variant_payload,
                )
                results.append(result)
        if skipped:
            print(f"  {ap}: resumed, skipped {skipped} finished cells")
        return results

    async def run_benign(self, trials: int) -> list[TrialResult]:
        """Run every benign scenario ``trials`` times.

        ``variant`` in the results is the scenario index (1-based), so the
        benign utility table can be broken down per scenario.
        """
        payloads = load_payloads(self.domain, "benign_alerts.json")
        if not payloads:
            payloads = load_payloads(self.domain, "benign_workflows.json")
        if not payloads:
            print(f"  No benign payloads for {self.domain}")
            return []

        done = self._done_cells()
        results = []
        for s_idx, payload in enumerate(payloads):
            for t in range(trials):
                if ("benign", str(s_idx + 1), str(t + 1)) in done:
                    continue
                result = await self.run_trial(
                    ap="benign",
                    variant=s_idx + 1,
                    trial=t + 1,
                    payload=payload,
                )
                results.append(result)
        return results

    def close(self):
        self.logger.close()


def print_summary(results: list[TrialResult], domain: str):
    """Print summary table of results."""
    if not results:
        return

    print(f"\n{'='*70}")
    print(f"TRIAL SUMMARY — {domain.upper()}")
    print(f"{'='*70}")

    # Group by AP + config
    from collections import defaultdict
    groups = defaultdict(list)
    for r in results:
        groups[(r.ap, r.config)].append(r)

    print(f"\n{'AP':<8} {'Config':<14} {'N':>4} {'Exec':>5} {'Block':>6} {'NotAtt':>7} "
          f"{'N/M':>4} {'Err':>4} {'ASR':>7} {'Attempt':>8} {'Block|Att':>10} {'Task':>6}")
    print("-" * 96)

    def pct(x):
        return "   n/a" if x is None else f"{100*x:5.1f}%"

    for (ap, config), trials in sorted(groups.items()):
        if ap == "benign":
            b = summarize_benign(trials)
            print(f"{ap:<8} {config:<14} {b['n']:>4}  task={pct(b['task_completed_rate'])} "
                  f"any_denial={pct(b['any_denial_rate'])} "
                  f"denials/incident={b['denials_per_incident'] if b['denials_per_incident'] is None else round(b['denials_per_incident'], 2)} "
                  f"err={b['error']}")
            continue
        m = summarize(trials)
        print(f"{ap:<8} {config:<14} {m['n']:>4} {m['executed']:>5} {m['blocked']:>6} "
              f"{m['not_attempted']:>7} {m['not_measurable']:>4} {m['error']:>4} "
              f"{pct(m['asr']):>7} {pct(m['attempt_rate']):>8} "
              f"{pct(m['block_rate_given_attempt']):>10} {pct(m['task_completed_rate']):>6}")


async def main():
    parser = argparse.ArgumentParser(description="DEFER Attack Harness")
    parser.add_argument("--domain", required=True, choices=["cyberops", "healthcare", "finance", "legal"])
    parser.add_argument("--ap", help="Specific attack path (ap1-ap6)")
    parser.add_argument("--eval", help="Evaluation suite (A=all CyberOps APs, F=domain-specific)")
    parser.add_argument("--config", default="agenticcyops",
                        help="flat, acl_hardened, agenticcyops, llm_judge, symbolic_only, "
                              "or all (= flat, acl_hardened, agenticcyops)")
    parser.add_argument("--trials", type=int, default=3, help="Trials per variant (default 3)")
    parser.add_argument("--benign", action="store_true", help="Run benign scenarios only")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--group", default="A", help="Model group (A-G)")
    parser.add_argument("--model-url", default="http://localhost:8000/v1")
    parser.add_argument("--llm-provider", default="openai", choices=["openai", "anthropic"])
    parser.add_argument("--consensus-config", default="default_consensus")
    parser.add_argument("--mma-url", default="http://localhost:9100")
    parser.add_argument("--tool-port", type=int, default=9000)
    parser.add_argument("--disable-principles", default="",
                        help="Comma-separated list of principles (P1-P5) "
                              "to disable for ablation studies. Only "
                              "affects the agenticcyops config. "
                              "Example: --disable-principles P3,P5")
    parser.add_argument("--api-key-env", default="",
                        help="Env-var name to read the primary LLM's API key "
                              "from (e.g. NVIDIA_API_KEY for cloud Nemotron). "
                              "Leave empty for self-hosted vLLM endpoints.")
    parser.add_argument("--extra-body-json", default="",
                        help="JSON string passed as `extra_body` on every "
                              "primary-LLM chat completion (model-specific "
                              "extras like NVIDIA's reasoning toggle).")
    parser.add_argument("--results-dir", default="",
                        help="Directory for results.csv (default "
                              "<RESULTS_DIR>/eval_attacks/group_<G>[_disabled_..]/<domain>/). "
                              "Rows are appended per trial; pass 'none' to disable.")
    parser.add_argument("--seed", type=int, default=None,
                        help="Base seed; trial t uses seed+t (recorded per trial).")
    parser.add_argument("--temperature", type=float, default=0.7,
                        help="Primary model sampling temperature (default 0.7; "
                              "validators always sample at 0).")
    parser.add_argument("--require-freeze", action="store_true",
                        help="Abort unless HEAD is exactly the defense-freeze tag "
                              "and the frozen directories are clean.")
    parser.add_argument("--resume", action="store_true",
                        help="Skip (ap, variant, trial, config) cells already present "
                              "in results.csv with a non-error outcome.")
    parser.add_argument("--run-tag", default="",
                        help="Suffix for the log directory (smoke, persistent) so special "
                              "runs never mix with the group's main logs.")
    parser.add_argument("--max-variants", type=int, default=None,
                        help="Only the first N variants of each attack path (smoke runs, E1b).")
    parser.add_argument("--state-mode", default="isolated", choices=["isolated", "persistent"],
                        help="isolated (default): reset every cross-incident defense "
                              "state and the MMA's trial documents before each trial; "
                              "persistent: let state accumulate as in production.")
    args = parser.parse_args()

    disabled = {p.strip().upper() for p in args.disable_principles.split(",")
                if p.strip()}
    extra_body = json.loads(args.extra_body_json) if args.extra_body_json.strip() else None
    configs = CONFIGS[:3] if args.config == "all" else [args.config]
    all_results = []

    for config in configs:
        print(f"\n--- Running {args.domain} / {config} / Group {args.group}"
              f"{' / disabled=' + ','.join(sorted(disabled)) if disabled else ''}"
              f" ---")
        harness = AttackHarness(
            domain=args.domain,
            config=config,
            group=args.group,
            llm_url=args.model_url,
            llm_provider=args.llm_provider,
            consensus_config=args.consensus_config,
            mma_url=args.mma_url,
            tool_base_port=args.tool_port,
            verbose=args.verbose,
            disabled_principles=disabled,
            api_key_env=(args.api_key_env or None),
            extra_body=extra_body,
            state_mode=args.state_mode,
            temperature=args.temperature,
            base_seed=args.seed,
            require_freeze=args.require_freeze,
            run_tag=args.run_tag,
        )
        if args.results_dir != "none":
            suffix = ("_disabled_" + "".join(sorted(disabled))) if disabled else ""
            rdir = Path(args.results_dir) if args.results_dir else (
                RESULTS_DIR / "eval_attacks" / f"group_{args.group}{suffix}" / args.domain)
            harness.results_csv = rdir / "results.csv"
        harness.resume = args.resume
        harness.max_variants = args.max_variants

        try:
            if args.benign:
                results = await harness.run_benign(args.trials)
                all_results.extend(results)

            elif args.eval == "A":
                for ap in CYBEROPS_APS:
                    print(f"  Running {ap}...")
                    results = await harness.run_ap(ap, args.trials)
                    all_results.extend(results)

            elif args.ap:
                results = await harness.run_ap(args.ap, args.trials)
                all_results.extend(results)

        finally:
            harness.close()

    print_summary(all_results, args.domain)


if __name__ == "__main__":
    asyncio.run(main())
