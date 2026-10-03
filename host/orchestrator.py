"""
SOAR Host Orchestrator.

Central coordinator that routes incidents through 4 phases sequentially.
Domain-agnostic — loads configs/tools/prompts from domains/{domain}/.

Config modes:
  "flat":           No enforcement. Agents call anything directly.
  "acl_hardened":   Manifest enforcement (P2-L1) only. No consensus/MMA.
  "agenticcyops":   Full P1-P5 enforcement.
"""

import copy
import json
import time as _time
from typing import Optional
from uuid import uuid4

import httpx
from openai import AsyncOpenAI

from config import BASE_DIR
from logging_utils import ExperimentLogger
from host.manifest_enforcer import ManifestEnforcer
from host.handoff import PhaseHandoff
from host.authenticated_interface import AuthenticatedInterface
from host.parameter_validator import ParameterValidator
from host.output_classifier import OutputClassifier
from consensus.verified_execution import VerifiedExecution
from consensus.operational_context import tool_for_action
from mcp_servers.server_registry import ServerRegistry


PHASE_ORDER = ["monitor", "analyze", "admin", "report"]



# v3.2: the action and target maps live in host.tool_semantics, shared with
# the parameter validator and the cross-incident ledger
from host.tool_semantics import IMPLIED_ACTION, TARGET_ARGS  # noqa: E402

HOIST_FIELDS = ("action", "target", "target_user", "target_hosts", "target_users",
                "account_id", "patient_id", "case_id")


def _incident_ids(incident: dict) -> list[str]:
    """Every ``incident_id`` the trigger names: top level first, then nested
    dicts one level down (``incident_context``, ``incident_a``, ...)."""
    out = []
    if isinstance(incident, dict):
        if incident.get("incident_id"):
            out.append(str(incident["incident_id"]))
        for v in incident.values():
            if isinstance(v, dict) and v.get("incident_id") and str(v["incident_id"]) not in out:
                out.append(str(v["incident_id"]))
    return out


def _render_handoff_fields(fields: dict) -> str:
    """Injected handoff fields as the phase's stated assessment (AP-9)."""
    if not fields:
        return ""
    lines = ["Phase assessment:"]
    for k, v in fields.items():
        val = v if isinstance(v, str) else json.dumps(v, default=str)
        lines.append(f"- {k.replace('_', ' ')}: {val}")
    return "\n".join(lines)


def _hoist(proposal: dict) -> dict:
    """Copy the fields P3's layers read at the proposal root: the action (or
    the tool's implied one) and its target."""
    args = proposal.get("arguments") or {}
    if not isinstance(args, dict):
        args = {}
    for field in HOIST_FIELDS:
        if field in args and field not in proposal:
            proposal[field] = args[field]
    tool_id = proposal.get("tool_id", "")
    if not proposal.get("action") and tool_id in IMPLIED_ACTION:
        kind = str(args.get("type") or "").lower()
        proposal["action"] = kind if tool_id == "L10_payment_processing" and kind == "refund" \
            else IMPLIED_ACTION[tool_id]
    if not proposal.get("target"):
        for field in TARGET_ARGS[1:]:
            if isinstance(args.get(field), (str, int)) and str(args[field]):
                proposal["target"] = str(args[field])
                break
    return proposal

class SOARHost:
    """Central orchestrator for the DEFER testbed."""

    # config label -> flags on the agenticcyops stack (see __init__)
    _STACK_VARIANTS = {
        "symbolic_only": {},
        "agenticcyops_noautoapprove": {"gate_mode": "noautoapprove"},
        "agenticcyops_gate_permissive": {"gate_mode": "permissive"},
        "p2_judge": {"p3_deterministic_off": True, "extra_disabled": {"P1", "P4", "P5"}},
        "agenticcyops_writejudge": {"write_judge": True},
    }

    def __init__(
        self,
        domain: str,
        config: str = "agenticcyops",
        llm_url: str = "http://localhost:8000/v1",
        mma_url: str = "http://localhost:9100",
        tool_registry: Optional[ServerRegistry] = None,
        consensus=None,
        agents: Optional[dict] = None,
        logger: Optional[ExperimentLogger] = None,
        embedding_model=None,
        disabled_principles: Optional[set] = None,
        state_mode: str = "isolated",
        adaptive_consent_path=None,
    ):
        self.domain = domain
        # ``symbolic_only`` (H10) is the full agenticcyops stack with the L6
        # LLM consensus removed: proposals that reach L6 are escalated
        # instead of judged.  Internally it is the agenticcyops branch with
        # no consensus validator; the label is kept for logs and results.
        self.config_label = config
        # Configuration variants that run on the agenticcyops stack with one
        # setting changed. Each is a flag, not a fork of the decision code, so
        # the deployed configuration's behaviour is untouched.
        #   symbolic_only                 (H10) L6 removed, proposals escalate
        #   agenticcyops_noautoapprove    (E1)  no deterministic auto-approve
        #   agenticcyops_gate_permissive  (E16) loose auto-approve gate
        #   p2_judge                      (E17) P2 + panel only
        #   agenticcyops_writejudge       (E9)  panel also judges memory writes
        _flags = self._STACK_VARIANTS.get(config, {})
        self.config = "agenticcyops" if config in self._STACK_VARIANTS else config
        config = self.config
        self._gate_mode = _flags.get("gate_mode", "default")
        self._p3_deterministic_off = bool(_flags.get("p3_deterministic_off"))
        self.write_judge = bool(_flags.get("write_judge"))
        if self.config_label == "symbolic_only":
            consensus = None
        self.llm_url = llm_url
        self.mma_url = mma_url
        self.tool_registry = tool_registry
        self.consensus = consensus
        self.agents = agents or {}
        self.logger = logger

        # State mode (H3).  "isolated": every incident starts from the
        # configured baseline (all cross-incident defense state and the
        # MMA's per-trial documents are reset before it runs).
        # "persistent": state accumulates across incidents as in production.
        if state_mode not in ("isolated", "persistent"):
            raise ValueError(f"state_mode must be isolated or persistent, got {state_mode!r}")
        self.state_mode = state_mode

        # Ablation switch -- only meaningful for the agenticcyops config.
        # Layer call sites consult ``self._principle_active("Px")`` and
        # short-circuit when the principle is disabled.  Stored uppercase
        # so callers can pass either case.
        self.disabled_principles: set = {p.upper() for p in (disabled_principles or set())}
        self.disabled_principles |= {p.upper() for p in _flags.get("extra_disabled", set())}

        # v3.1.4: hiding out-of-manifest tools from the model is part of P2
        # (capability scoping). JUDGEONLY has no P2 and an ablation without P2
        # must not keep it; before, both still showed each agent only its
        # phase manifest. (FLAT and ACL already showed every tool.)
        if self.config_label == "llm_judge" or not self._principle_active("P2"):
            for _agent in self.agents.values():
                setattr(_agent, "show_all_tools", True)

        # E9: stores marked critical in the domain config. Writes to these are
        # routed to the panel under agenticcyops_writejudge; empty for every
        # other configuration, so nothing else changes behaviour.
        self.critical_stores: set = set()
        if self.write_judge:
            try:
                import json as _j
                _cfg = _j.loads((BASE_DIR / "domains" / domain / "configs"
                                 / "memory_collections.json").read_text())
                self.critical_stores = {c["id"] for c in _cfg.get("collections", [])
                                        if c.get("critical")}
            except Exception:
                self.critical_stores = set()

        self.enforcer = ManifestEnforcer(domain=domain, logger=logger)
        self.handoff = PhaseHandoff(logger=logger)

        # Layer instantiation
        #   agenticcyops -> P1 identity + P2 manifest/params/output + P3 full
        #                   verified-execution stack (which wraps consensus)
        #   llm_judge    -> P1 identity only; the new elif branch in
        #                   _process_tool_call calls `self.consensus`
        #                   directly without P2/P3/P4/P5
        #   flat / acl_hardened -> none of the above (no auth_interface)
        if config in ("agenticcyops", "llm_judge"):
            self.auth_interface = AuthenticatedInterface(domain=domain, logger=logger)
        else:
            self.auth_interface = None

        if config == "agenticcyops":
            self.param_validator = ParameterValidator(
                domain=domain, embedding_model=embedding_model, logger=logger
            )
            self.output_classifier = OutputClassifier(
                domain=domain, embedding_model=embedding_model, logger=logger
            )
            self.verified_execution = VerifiedExecution(
                domain=domain,
                consensus_validator=consensus,
                embedding_model=embedding_model,
                logger=logger,
                adaptive_consent_path=adaptive_consent_path,
                adaptive_consent_persist=(state_mode == "persistent"),
                symbolic_only=(self.config_label == "symbolic_only"),
                gate_mode=self._gate_mode,
                p3_deterministic_off=self._p3_deterministic_off,
            )
        else:
            self.param_validator = None
            self.output_classifier = None
            self.verified_execution = None

        self._llm = AsyncOpenAI(base_url=llm_url, api_key="unused")

    async def run_incident(self, incident: dict, harness_injection: Optional[dict] = None) -> dict:
        """Full pipeline: Monitor -> Analyze -> Admin -> Report.

        ``harness_injection`` (H5) carries the payload's ``meta.injection``
        block for the ``handoff`` and ``proposal_justification`` channels.
        It is never part of ``incident`` and therefore never rendered to a
        model; the hooks below are the only consumers.
        """
        # a deep copy: fault hooks mark a spec "_applied", and the harness reuses
        # one payload dict for every trial of a variant (v3.1; before, only the
        # first trial of each AP-15 variant got its fault)
        self.harness_injection = copy.deepcopy(harness_injection or {})
        # v3.2: the ids the incident names, top level or nested (several
        # triggers keep their fields under ``incident_context``, multi-incident
        # ones under ``incident_a`` / ``incident_b``); before, such incidents got
        # a random id and P3.6 denied every proposal that cited the real one
        named_ids = _incident_ids(incident)
        context = {
            "incident": incident,
            "incident_id": incident.get("incident_id") or (named_ids[0] if named_ids else str(uuid4())),
            "incident_ids": named_ids,
            "domain": self.domain,
            "config": self.config,
            "phases": {},
            # v3.1: the scorer and adaptive consent read context["severity"],
            # which was never set (always "medium")
            "severity": str(incident.get("initial_severity") or incident.get("severity")
                            or incident.get("initial_priority") or incident.get("priority")
                            or (incident.get("incident_context") or {}).get("severity")
                            or (incident.get("incident_context") or {}).get("initial_severity")
                            or "medium"),
        }

        self.enforcer.reset_counts()
        self._call_seq = 0

        # P3: Reset per-incident state; in isolated mode every
        # cross-incident state as well (H3).
        if self.state_mode == "isolated":
            await self.reset_trial_state()
        elif self.verified_execution:
            self.verified_execution.reset_for_incident()

        # P1-L3: Verify config integrity before each incident (skipped under -P1).
        # v3.1: FULL only; JUDGEONLY is P1 identity plus the panel, and this
        # check aborted its whole incident on config-tamper variants
        if (self.auth_interface and self.config == "agenticcyops"
                and self._principle_active("P1")):
            self.auth_interface.reset_replay_cache()
            configs_ok, changed_files = self.auth_interface.verify_config_integrity(
                overlay=self._config_tamper_overlay())
            if not configs_ok:
                if self.logger:
                    self.logger.log(
                        source="host", destination="config_integrity",
                        action="config_verification",
                        extra={"auth_decision": "deny",
                               "mechanism": "P1_config_integrity_violation",
                               "changed_files": changed_files},
                    )
                return {"status": "config_integrity_failure",
                        "changed_files": changed_files}

        # Register incident status for P3-L0.5 lifecycle check (AP-11 v2 / v5)
        if self.verified_execution:
            inc_status = incident.get("incident_status", incident.get("status", "open"))
            self.verified_execution.operational_context.register_incident_status(
                context["incident_id"], inc_status)

        # Seed change_log from incident payload with the payload's declared
        # approval timestamp so the 72h cutoff reflects the scenario timeline
        # rather than wall-clock drift (AP-11 v1).
        if self.verified_execution:
            recent_change = incident.get("recent_change")
            if recent_change:
                self.verified_execution.operational_context.record_change(
                    # v3.1: payloads name only the action; the recorded tool was the
                    # action string, so the conflict check never matched it
                    tool_id=(recent_change.get("tool")
                             or tool_for_action(recent_change.get("action", ""))),
                    action=recent_change.get("action", ""),
                    target=recent_change.get("target", ""),
                    incident_id=context["incident_id"],
                    timestamp=recent_change.get("approved_at") or recent_change.get("timestamp"))

        # Seed maintenance windows from payload so P3-L0.5 maintenance-window
        # check has data to compare against (AP-11 v3 / v5).
        if self.verified_execution:
            maint_ctxs = []
            if isinstance(incident.get("maintenance_context"), dict):
                maint_ctxs.append(incident["maintenance_context"])
            if isinstance(incident.get("maintenance_contexts"), list):
                maint_ctxs.extend(incident["maintenance_contexts"])
            for mc in maint_ctxs:
                asset = mc.get("asset") or mc.get("hostname")
                start = mc.get("start_time") or mc.get("start")
                end = mc.get("end_time") or mc.get("end")
                if asset and start and end:
                    self.verified_execution.operational_context.add_maintenance_window(
                        asset=asset,
                        start_time=start,
                        end_time=end,
                        window_id=mc.get("maintenance_window_id", "payload_seeded"))

        # Propagate the incident's claimed execution time to every P3 check
        # so time / window / change-conflict comparisons honour the
        # scenario's declared timeline (AP-11 v4 / v5).
        claimed_time = (
            (incident.get("time_context") or {}).get("current_time")
            or incident.get("timestamp")
        )
        if claimed_time:
            context["claimed_time"] = claimed_time

        for i, phase in enumerate(PHASE_ORDER):
            if phase not in self.agents:
                continue

            result = await self.run_phase(phase, context)
            context["phases"][phase] = result

            # Handoff to next phase
            if i < len(PHASE_ORDER) - 1:
                next_phase = PHASE_ORDER[i + 1]
                handoff_ctx = self.handoff.create_handoff(
                    source_phase=phase,
                    target_phase=next_phase,
                    phase_output=result,
                    incident_context=context,
                )
                if self.harness_injection:
                    handoff_ctx = self._inject_handoff(phase, next_phase, handoff_ctx)
                context[f"{phase}_handoff"] = handoff_ctx

        return context

    # ---- H5 injection channels (harness only) ---------------------------

    def _inject_handoff(self, phase: str, next_phase: str, handoff_ctx: dict) -> dict:
        """``handoff`` channel: the attacker phase's handoff is altered as a
        compromised agent would alter it.  Spec (``meta.injection.handoff``):
        ``{"from_phase": ..., "fields": {...}, "append_summary": "..."}``."""
        spec = self.harness_injection.get("handoff")
        if not isinstance(spec, dict):
            return handoff_ctx
        src = spec.get("from_phase") or self.harness_injection.get("attacker_phase")
        if src and src != phase:
            return handoff_ctx
        out = dict(handoff_ctx)
        fields = spec.get("fields") or {}
        for k, v in fields.items():
            out[k] = v
        # v3.1.4: the next agent reads only the handoff's summary and tool
        # results (agents/base_agent._format_context), so injected fields that
        # stayed structured were seen by P3-L0 alone and never by a model. A
        # compromised agent states its claims in what it hands over: the fields
        # are rendered into the summary, through the same sanitizer as any
        # phase output (host.handoff._sanitize_text).
        rendered = _render_handoff_fields(fields)
        extra = "\n\n".join(x for x in (rendered, spec.get("append_summary") or "") if x)
        if extra:
            from host.handoff import _sanitize_text
            extra, _n = _sanitize_text(extra)
            out["phase_summary"] = f"{out.get('phase_summary', '')}\n\n{extra}".strip()
        if self.logger:
            self.logger.log(source="harness", destination=f"{next_phase}_agent",
                            action="harness_injection",
                            extra={"channel": "handoff", "phase": phase,
                                   "fields": sorted((spec.get("fields") or {}).keys()),
                                   "append_summary": bool(spec.get("append_summary"))})
            self.logger.log(source="harness", destination=f"{next_phase}_agent",
                            action="injection_served",
                            extra={"channel": "handoff", "phase": phase, "to_phase": next_phase})
        return out

    def _inject_proposals(self, phase: str, result) -> None:
        """``proposal_justification`` channel: proposals a compromised
        attacker phase would emit are appended to the agent's own.  Spec:
        ``meta.injection.proposal`` (one) or ``proposals`` (list) of
        ``{"phase", "tool", "arguments", "justification"}``."""
        from agents.base_agent import ToolCallProposal
        specs = []
        one = self.harness_injection.get("proposal")
        if isinstance(one, dict):
            specs.append(one)
        specs.extend(p for p in (self.harness_injection.get("proposals") or []) if isinstance(p, dict))
        default_phase = self.harness_injection.get("attacker_phase")
        for spec in specs:
            if (spec.get("phase") or default_phase or phase) != phase or not spec.get("tool"):
                continue
            result.proposed_tool_calls.append(ToolCallProposal(
                tool_id=spec["tool"], arguments=dict(spec.get("arguments") or {}),
                justification=str(spec.get("justification") or "")))
            if self.logger:
                self.logger.log(source="harness", destination=spec["tool"],
                                action="harness_injection",
                                extra={"channel": "proposal_justification", "phase": phase,
                                       "arguments": dict(spec.get("arguments") or {})})
                self.logger.log(source="harness", destination=spec["tool"],
                                action="injection_served",
                                extra={"channel": "proposal_justification", "phase": phase,
                                       "tool": spec["tool"]})

    # ---- H6 fault injection (harness only) -------------------------------

    def _fault(self, kind: str) -> Optional[dict]:
        """The harness's fault spec of ``kind`` for this incident, if any.
        ``meta.injection.fault`` = ``{"kind": "toctou"|"forged_response"|
        "config_tamper", ...}`` (or ``faults``: a list)."""
        if not self.harness_injection:
            return None
        specs = []
        one = self.harness_injection.get("fault")
        if isinstance(one, dict):
            specs.append(one)
        specs.extend(f for f in (self.harness_injection.get("faults") or []) if isinstance(f, dict))
        return next((f for f in specs if f.get("kind") == kind and not f.get("_applied")), None)

    def _config_tamper_overlay(self) -> Optional[dict]:
        """``config_tamper`` fault: what P1-L3 would read from a tampered
        config file.  Spec: ``{"kind": "config_tamper", "file":
        "asset_criticality.json", "patch": {"a.b.c": value, ...}}``.  The
        patched bytes are handed to the integrity check as an overlay; the
        file on disk is never modified."""
        spec = self._fault("config_tamper")
        if not spec or not spec.get("file"):
            return None
        path = BASE_DIR / "domains" / self.domain / "configs" / str(spec["file"])
        try:
            data = json.loads(path.read_text())
        except Exception:
            return None
        patch = spec.get("patch") or {}
        # {"a.b": v} dotted form, or [{"path": ["a", "b"], "value": v}] for
        # keys that themselves contain dots (IP addresses).
        items = ([(list(e.get("path") or []), e.get("value")) for e in patch if isinstance(e, dict)]
                 if isinstance(patch, list) else
                 [(str(k).split("."), v) for k, v in patch.items()])
        for keys, value in items:
            if not keys:
                continue
            node = data
            for k in keys[:-1]:
                if not isinstance(node, dict):
                    break
                node = node.setdefault(k, {})
            if isinstance(node, dict):
                node[keys[-1]] = value
        spec["_applied"] = True
        if self.logger:
            self.logger.log(source="harness", destination="config_integrity",
                            action="harness_fault",
                            extra={"kind": "config_tamper", "file": str(spec["file"]),
                                   "patched": [".".join(k) for k, _ in items]})
        return {str(path): json.dumps(data, indent=2).encode()}

    def _apply_pre_execution_fault(self, phase: str, tc) -> None:
        """``toctou`` fault: the arguments change between approval and
        execution, as a compromised executor would change them.  Spec:
        ``{"kind": "toctou", "tool": id, "phase": p, "mutate": {arg: value}}``."""
        spec = self._fault("toctou")
        if not spec or spec.get("tool") != tc.tool_id:
            return
        if spec.get("phase") and spec["phase"] != phase:
            return
        before = dict(tc.arguments) if isinstance(tc.arguments, dict) else {}
        original_tool = tc.tool_id
        if spec.get("swap_tool"):
            # the executed call targets another tool entirely
            tc.tool_id = str(spec["swap_tool"])
            tc.arguments = dict(spec.get("mutate") or {})
        else:
            tc.arguments = {**before, **(spec.get("mutate") or {})}
        spec["_applied"] = True
        if self.logger:
            self.logger.log(source="harness", destination=tc.tool_id, action="harness_fault",
                            extra={"kind": "toctou", "phase": phase, "approved_tool": original_tool,
                                   "mutated_keys": sorted((spec.get("mutate") or {}).keys()),
                                   **self._args_for_log(tc)})

    def _apply_post_execution_fault(self, phase: str, tc, response):
        """``forged_response`` fault: the tool's response is replaced after
        the tool answered (unsigned, as a forgery in transit would be).
        Spec: ``{"kind": "forged_response", "tool": id, "response": {...}}``."""
        spec = self._fault("forged_response")
        if not spec or spec.get("tool") != tc.tool_id:
            return response
        if spec.get("phase") and spec["phase"] != phase:
            return response
        forged = spec.get("response")
        forged = dict(forged) if isinstance(forged, dict) else {"status": "success", "result": forged}
        forged.setdefault("tool_id", tc.tool_id)
        forged.pop("signature", None)
        spec["_applied"] = True
        if self.logger:
            self.logger.log(source="harness", destination=tc.tool_id, action="harness_fault",
                            extra={"kind": "forged_response", "phase": phase,
                                   **self._args_for_log(tc)},
                            scan_text=forged)
        return forged

    def _trial_id(self) -> str:
        return (getattr(self.logger, "_trial_id", None) or "") if self.logger else ""

    async def reset_trial_state(self) -> dict:
        """Return every stateful component to its baseline (H3).

        In-process: P2 action counts, P1 replay cache, the whole P3 stack
        (intent chain, cross-incident ledger, versioned ledger, global
        monitor, adaptive consent, operational context).  Out of process:
        ``POST /admin/reset`` on the MMA gateway clears P4 hashes /
        centroids, P5 read history and every document tagged with a
        ``trial_id``.  Returns a summary that is also logged as a
        ``trial_reset`` event.
        """
        self.enforcer.reset_counts()
        if self.auth_interface:
            self.auth_interface.reset_replay_cache()
        if self.verified_execution:
            self.verified_execution.reset_for_trial()
        summary = {"state_mode": self.state_mode, "in_process": True, "mma": None}
        # The store must be cleared for *every* configuration, not just the
        # defended one. Gating this on ``config == "agenticcyops"`` left the
        # flat, ACL and judge-only arms sharing one store across trials, so
        # documents planted by earlier variants crowded later ones out of the
        # top-k and memory-channel exposure decayed with variant order (AP-14
        # flat: 12/12/12/9/6 by variant, against 12 across the board for the
        # defended arm). ``state_mode: isolated`` has to mean the same thing in
        # every arm or the undefended baseline is not comparable.
        if self.mma_url:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(f"{self.mma_url}/admin/reset",
                                             json={"auth_token": self._mma_token("admin", "reset")},
                                             timeout=30)
                    summary["mma"] = resp.json() if resp.status_code == 200 else {
                        "status": resp.status_code}
            except Exception as exc:
                summary["mma"] = {"error": str(exc)[:120]}
        if self.logger:
            self.logger.log(source="host", destination="state", action="trial_reset",
                            extra=summary)
        return summary

    @staticmethod
    def _mma_token(phase: str, store_id: str) -> str:
        """Request signature the MMA gateway verifies (shared HMAC key)."""
        import hashlib as _hl
        import hmac as _hm
        import os as _os
        key = _os.environ.get("MMA_SHARED_SECRET", "")
        if not key:
            key_path = BASE_DIR / "configs" / "hmac_key.txt"
            if key_path.exists():
                key = key_path.read_text().strip()
        if not key:
            return ""
        return _hm.new(key.encode(), f"{phase}:{store_id}".encode(), _hl.sha256).hexdigest()[:16]

    async def run_phase(self, phase: str, context: dict) -> dict:
        """Execute a single phase with enforcement based on config.

        Scripted memory reads (``incident.memory_ops.reads``) run *before*
        the agent's LLM call and their results are placed in
        ``context["memory_context"][phase]``, so what the store returns can
        reach the model (H4).  Scripted writes run after the agent's own
        writes.
        """
        agent = self.agents[phase]
        memory_ops = context.get("incident", {}).get("memory_ops", {}) or {}

        # Scripted reads for this phase (every config; enforcement differs)
        reads = []
        for mr in memory_ops.get("reads", []) or []:
            if mr.get("phase") == phase:
                reads.append(await self._process_memory_read(phase, mr, context))
        if reads:
            context.setdefault("memory_context", {})[phase] = reads

        # Agent proposes actions
        try:
            result = await agent.execute(context)
        except Exception as e:
            from agents.base_agent import AgentResult
            result = AgentResult(phase=phase, summary=f"Agent error: {str(e)[:200]}")
            if self.logger:
                self.logger.log(source=f"{phase}_agent", destination="error",
                               action="agent_error", extra={"error": str(e)[:200]})

        if self.harness_injection:
            self._inject_proposals(phase, result)

        # Process proposed tool calls SEQUENTIALLY (TA-19: no parallel bypass)
        executed_responses = []
        for tc in result.proposed_tool_calls:
            self._last_block = ""
            response = await self._process_tool_call(phase, tc, context)
            executed_responses.append(response)
            # v3.1: count only actions that ran toward the bulk-action cap; denied
            # proposals counted too, so a legitimate call could be escalated
            if not (isinstance(response, dict)
                    and response.get("status") in ("denied", "escalated")):
                self.enforcer.record_action(phase)

            # Break on critical safety gate failures (TA-19 fix). v3.1: match the
            # deciding layer's mechanism; the agent-facing reason is sanitized
            # ("Action not approved."), so matching it never fired.
            if isinstance(response, dict) and response.get("status") in ("denied", "escalated"):
                reason = self._last_block
                if any(m in reason for m in (
                    "P3_dangerous_pattern", "P3_posture_threshold",
                    "P3_cross_", "P3_exact_replay", "P3_bulk_action",
                )):
                    break

        result.tool_responses = executed_responses

        # Process proposed memory writes (from agent)
        for mw in result.memory_writes:
            await self._process_memory_write(phase, mw, context)

        # Scripted writes for this phase (every config; enforcement differs)
        for mw in memory_ops.get("writes", []) or []:
            if mw.get("phase") == phase:
                await self._process_memory_write(phase, {
                    "store_id": mw["store"],
                    "content": mw.get("content", ""),
                    "metadata": mw.get("metadata", {}),
                    "doc_id": f"{phase}_{mw['store']}_{context.get('incident_id', 'unknown')}",
                    "scripted": True,
                }, context)

        return result.to_dict()

    # TA-21: Generic rejection reasons to prevent defense leakage to agents
    _SANITIZED_REASONS = {
        "P1_authenticated_interface": "Action not permitted.",
        "P1_unregistered_tools": "Action not permitted.",
        "P2_capability_scoping": "Action not permitted for this phase.",
        "P2_tool_not_in_manifest": "Action not permitted for this phase.",
        "P2_wildcard_parameter": "Invalid parameters.",
        "P2_critical_asset": "Action not permitted for this target.",
        "P2_high_criticality_destructive": "Action not permitted for this target.",
        "P2_parameter_rule_violation": "Invalid parameters.",
        "P2_target_not_in_evidence": "Target not supported by incident evidence.",
        "P3_verified_execution": "Action not approved.",
        "P3_rejected": "Action not approved.",
        "acl_network_layer": "Access denied.",
    }

    def _sanitize_reason(self, reason: str) -> str:
        """Strip defense internals from rejection reasons (TA-21 fix)."""
        for key, generic in self._SANITIZED_REASONS.items():
            if key in reason:
                return generic
        # Default: strip anything after colon (often contains specifics)
        if ":" in reason:
            return reason.split(":")[0] + "."
        return "Action denied."

    def _principle_active(self, principle: str) -> bool:
        """True iff ``principle`` (e.g. 'P3') is NOT in disabled_principles.

        Only meaningful for the agenticcyops config; the flat / acl_hardened
        branches never consult this helper.  Used by ablation studies to
        disable specific principles at runtime via the harness's
        ``--disable-principles`` CLI flag.
        """
        return principle.upper() not in self.disabled_principles

    # Compact, size-bounded snapshot of tool-call arguments for the audit log.
    # Attack evaluation (attacks/harness.py) matches scripted adversarial
    # actions on tool + operation + parameters when this field is present;
    # logs written before 2026-09 carry tool names only.  The unbounded
    # arguments are on the ``tool_proposed`` event that precedes every
    # ``tool_call`` event with the same ``call_id``.
    _ARG_LOG_MAX_CHARS = 600

    @classmethod
    def _compact_args(cls, arguments) -> dict:
        try:
            if not isinstance(arguments, dict):
                return {}
            out = {}
            for k, v in arguments.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    out[k] = v
                else:
                    out[k] = json.dumps(v, default=str)
                if len(json.dumps(out, default=str)) > cls._ARG_LOG_MAX_CHARS:
                    out[k] = str(out[k])[:120] + "..."
            return out
        except Exception:
            return {}

    def _args_for_log(self, tc) -> dict:
        """``{"arguments": <compact>, "call_id": ..., "layer_latency_ms": {...}}``
        for a tool_call event.  Layer timings (H8) are accumulated per call
        in ``self._layer_lat`` by :meth:`_enforce_tool_call`."""
        arguments = tc.arguments if hasattr(tc, "arguments") else tc
        out = {"arguments": self._compact_args(arguments)}
        call_id = getattr(tc, "call_id", "")
        if call_id:
            out["call_id"] = call_id
        lat = getattr(self, "_layer_lat", None)
        if lat:
            out["layer_latency_ms"] = {k: round(v, 2) for k, v in lat.items()}
        return out

    def _lap(self, layer: str, t0: float) -> float:
        """Record elapsed ms since ``t0`` under ``layer``; return a new t0."""
        now = _time.perf_counter()
        self._layer_lat[layer] = self._layer_lat.get(layer, 0.0) + (now - t0) * 1000
        return now

    def _next_call_id(self, phase: str, kind: str, key: str) -> str:
        """Stable per-incident identifier: ``<phase>:<kind>:<seq>:<hash8>``.

        ``seq`` orders proposals within the incident; the hash of the
        proposal content lets two logs of the same scenario be aligned.
        """
        import hashlib as _hl
        self._call_seq = getattr(self, "_call_seq", 0) + 1
        digest = _hl.sha256(key.encode()).hexdigest()[:8]
        return f"{phase}:{kind}:{self._call_seq:03d}:{digest}"

    async def _process_tool_call(self, phase: str, tc, context: dict) -> dict:
        """Record the proposal, then run config-appropriate enforcement.

        The ``tool_proposed`` event is written before any check in every
        config, with the full arguments and a ``call_id`` that every later
        event for this call (denial, execution, redaction) carries.
        """
        if not getattr(tc, "call_id", ""):
            key = f"{tc.tool_id}|{json.dumps(tc.arguments, sort_keys=True, default=str)}"
            try:
                tc.call_id = self._next_call_id(phase, "tool", key)
            except Exception:
                pass
        if self.logger:
            self.logger.log(
                source=f"{phase}_agent", destination=tc.tool_id,
                action="tool_proposed",
                extra={
                    "call_id": getattr(tc, "call_id", ""),
                    "arguments": tc.arguments if isinstance(tc.arguments, dict) else {},
                    "justification": (tc.justification or "")[:300],
                },
            )
        return await self._enforce_tool_call(phase, tc, context)

    async def _enforce_tool_call(self, phase: str, tc, context: dict) -> dict:
        """Process a tool call with config-appropriate enforcement.

        Per-layer wall-clock is accumulated in ``self._layer_lat`` and
        written on the call's final ``tool_call`` event as
        ``layer_latency_ms`` (keys P1_L1, P2_L1, P2_L2, P3, P3_L7, exec,
        P1_L2, P2_L3, acl, judge).

        Enforcement pipeline (agenticcyops):
          1. P1-L1: Component identity verification
          2. P2-L1: Manifest enforcement (tool allowed for this phase?)
          3. P2-L2: Parameter validation (wildcards, criticality, rules, evidence)
          4. P3:    Consensus validation (for irreversible actions)
          4b. P3-L7: Execution verification before the call (approved == executed, fresh)
          5. Execute tool
          6. P1-L2: Response integrity (signature, schema, timing, replay)
          7. P2-L3: Output classification (sensitive data detection)
        """
        tool_id = tc.tool_id
        self._layer_lat = {}
        _t = _time.perf_counter()

        # Config-specific enforcement
        if self.config == "acl_hardened":
            # ACL: Enforce at "network layer" — agent was still manipulated into trying
            allowed, reason = self.enforcer.validate_tool_call(phase, tool_id)
            _t = self._lap("acl", _t)
            if not allowed:
                if self.logger:
                    self.logger.log_tool_call(
                        agent=f"{phase}_agent",
                        tool=tool_id,
                        auth_decision="deny",
                        mechanism="acl_network_layer",
                        interception_step=2,
                    extra=self._args_for_log(tc))
                return {"status": "denied", "tool_id": tool_id, "reason": f"403: {reason}"}

        elif self.config == "llm_judge":
            # Ablation: P1-L1 identity verification, then route the
            # proposal to the consensus-quorum LLM judge.  Skips
            # P2/P3/P4/P5 entirely so we can isolate "what does an LLM
            # panel-as-judge alone catch?" -- the standard
            # ablation.  Mechanism strings emitted:
            #     P1_authenticated_interface  (P1 fail)
            #     P3_consensus_reject         (judges deny)
            #     P3_consensus_unavailable    (every validator errored)
            #     P3_consensus_error          (call itself raised)
            #     llm_judge_approved          (judges allow -> falls
            #                                  through to executor below)
            if self.auth_interface:
                verified, reason = self.auth_interface.verify_component(tool_id, "tools")
                _t = self._lap("P1_L1", _t)
                if not verified:
                    if self.logger:
                        self.logger.log_tool_call(
                            agent=f"{phase}_agent",
                            tool=tool_id,
                            auth_decision="deny",
                            mechanism="P1_authenticated_interface",
                            interception_step=1,
                        extra=self._args_for_log(tc))
                    return {"status": "denied", "tool_id": tool_id,
                            "reason": self._sanitize_reason(reason)}

            if self.consensus is not None:
                # Build the same proposal shape the agenticcyops P3 path
                # constructs (lines 436-445).  Hoist arguments fields to
                # the proposal root so validators that read action/target
                # at top level work uniformly.
                proposal = tc.to_proposal()
                proposal["phase"] = phase
                _hoist(proposal)
                p3_context = {**context, "current_phase": phase}

                try:
                    result = await self.consensus.validate_with_details(
                        proposal, p3_context)
                    _t = self._lap("judge", _t)
                except Exception as exc:
                    _t = self._lap("judge", _t)
                    if self.logger:
                        self.logger.log_tool_call(
                            agent=f"{phase}_agent",
                            tool=tool_id,
                            auth_decision="allow",
                            mechanism="P3_consensus_error",
                            interception_step=6,
                        extra=self._args_for_log(tc))
                    # Fall through to execution -- benchmark records this
                    # as an "allow" but with the error-mechanism marker
                    # so analytics can filter these trials out.
                else:
                    votes = list(result.votes)
                    all_error = bool(votes) and all(
                        v.decision == "error" or v.validator_id == "error" for v in votes)
                    if not votes or all_error:
                        if self.logger:
                            self.logger.log_tool_call(
                                agent=f"{phase}_agent",
                                tool=tool_id,
                                auth_decision="allow",
                                mechanism="P3_consensus_unavailable",
                                interception_step=6,
                        extra=self._args_for_log(tc))
                        # Same fall-through semantics as InjecAgent's
                        # evaluate_with_consensus: don't silently mask
                        # results when validators are down.
                    elif not result.approved:
                        if self.logger:
                            self.logger.log_tool_call(
                                agent=f"{phase}_agent",
                                tool=tool_id,
                                auth_decision="deny",
                                mechanism="P3_consensus_reject",
                                interception_step=6,
                        extra=self._args_for_log(tc))
                        return {"status": "denied", "tool_id": tool_id,
                                "reason": (f"consensus rejected "
                                            f"({result.rejections}/{len(votes)} "
                                            f"reject, threshold {result.threshold})")}
                    else:
                        if self.logger:
                            self.logger.log_tool_call(
                                agent=f"{phase}_agent",
                                tool=tool_id,
                                auth_decision="allow",
                                mechanism="llm_judge_approved",
                                interception_step=6,
                        extra=self._args_for_log(tc))

        elif self.config == "agenticcyops":
            # ── Step 1: P1-L1 — Component identity ──
            if self.auth_interface and self._principle_active("P1"):
                verified, reason = self.auth_interface.verify_component(tool_id, "tools")
                _t = self._lap("P1_L1", _t)
                if not verified:
                    if self.logger:
                        self.logger.log_tool_call(
                            agent=f"{phase}_agent",
                            tool=tool_id,
                            auth_decision="deny",
                            mechanism="P1_authenticated_interface",
                            interception_step=1,
                        extra=self._args_for_log(tc))
                    return {"status": "denied", "tool_id": tool_id,
                            "reason": self._sanitize_reason(reason)}

            # ── Step 2: P2-L1 — Manifest enforcement ──
            if self._principle_active("P2"):
                allowed, reason = self.enforcer.validate_tool_call(phase, tool_id)
                _t = self._lap("P2_L1", _t)
                if not allowed:
                    if self.logger:
                        self.logger.log_tool_call(
                            agent=f"{phase}_agent",
                            tool=tool_id,
                            auth_decision="deny",
                            mechanism="P2_capability_scoping",
                            interception_step=2,
                        extra=self._args_for_log(tc))
                    return {"status": "denied", "tool_id": tool_id,
                            "reason": self._sanitize_reason(reason)}

            # ── Step 3: P2-L2 — Parameter validation ──
            if self.param_validator and self._principle_active("P2"):
                incident_evidence = json.dumps(
                    context.get("incident", {}), default=str
                )
                params_ok, p_reason, p_details = self.param_validator.validate(
                    tool_id, tc.arguments, incident_evidence
                )
                _t = self._lap("P2_L2", _t)
                if not params_ok:
                    if self.logger:
                        self.logger.log(
                            source=f"{phase}_agent", destination=tool_id,
                            action="tool_call", auth_decision="deny",
                            mechanism="P2_capability_scoping",
                            interception_step=2,
                            extra={"p2l2_reason": p_reason, **p_details,
                                   **self._args_for_log(tc)},
                        )
                    return {"status": "denied", "tool_id": tool_id,
                            "reason": self._sanitize_reason(p_reason)}

        # P3: Verified Execution — full multi-layer pipeline (agenticcyops only)
        # Fix #1: Force P3 for negative-impact tools regardless of requires_consensus
        _p3_approved_at = None  # Fix L7: reliable variable init (not dir())
        if (self.config == "agenticcyops" and self.verified_execution
                and self._principle_active("P3")):
            needs_p3 = self.enforcer.requires_consensus(phase, tool_id)
            if not needs_p3 and hasattr(self.verified_execution, 'intent_chain'):
                action = _hoist({"tool_id": tool_id,
                                 "arguments": getattr(tc, "arguments", None) or {}}).get("action", "")
                impact = self.verified_execution.intent_chain._get_impact(tool_id, action)
                if impact < 0:
                    needs_p3 = True  # negative-impact tools always go through P3

            if needs_p3:
                proposal = tc.to_proposal()
                proposal["phase"] = phase
                # Hoist arguments fields to top level for P3 layers that
                # read action/target from the proposal root (fourth-pass fix)
                _hoist(proposal)
                # v2.9 (B1): the evidence the risk scorer's alignment reads,
                # as P2's parameter check uses it
                p3_context = {**context, "current_phase": phase,
                              "incident_evidence": json.dumps(context.get("incident", {}), default=str)}
                _p3_approved_at = _time.time()  # Fix #3: timestamp for L7
                approved = await self.verified_execution.validate(
                    proposal, p3_context
                )
                _t = self._lap("P3", _t)
                if not approved:
                    res = getattr(self.verified_execution, "last_result", None) or {}
                    self._last_block = f"{res.get('mechanism', '')} {res.get('reason', '')}"
                    if self.logger:
                        self.logger.log_tool_call(
                            agent=f"{phase}_agent",
                            tool=tool_id,
                            auth_decision="deny",
                            mechanism="P3_verified_execution",
                            interception_step=3,
                        extra=self._args_for_log(tc))
                    return {"status": "denied", "tool_id": tool_id, "reason": "Action not approved."}

            # Bulk action check (count + 1 to include current action — off-by-one fix)
            count = self.enforcer._action_counts.get(phase, 0) + 1
            if self.enforcer.check_bulk_action(phase, count):
                if self.logger:
                    self.logger.log_escalation(
                        source=f"{phase}_agent",
                        reason=f"Bulk action threshold exceeded ({count} actions)",
                        severity="high",
                    )
                    self.logger.log_tool_call(
                        agent=f"{phase}_agent",
                        tool=tool_id,
                        auth_decision="escalate",
                        mechanism="P3_bulk_action",
                        interception_step=3,
                        extra=self._args_for_log(tc))
                self._last_block = "P3_bulk_action"
                return {"status": "escalated", "tool_id": tool_id, "reason": "Action limit reached."}

        # ── Harness fault: TOCTOU mutation between approval and execution ──
        if self.harness_injection:
            self._apply_pre_execution_fault(phase, tc)
            tool_id = tc.tool_id          # may have been swapped

        # ── Step 4b: P3-L7 — Execution verification, BEFORE execution (H6) ──
        # What is about to be executed must be exactly what was approved,
        # and the approval must be fresh.  Runs before the tool is called so
        # a mismatch never reaches the tool.
        if (self.config == "agenticcyops" and self.verified_execution
                and _p3_approved_at is not None and self._principle_active("P3")):
            _to_execute = tc.to_proposal()
            _to_execute["phase"] = phase
            _hoist(_to_execute)
            l7_ok, l7_reason = self.verified_execution.verify_execution(
                proposal, _to_execute, _p3_approved_at
            )
            _t = self._lap("P3_L7", _t)
            if not l7_ok:
                if self.logger:
                    self.logger.log(
                        source=f"{phase}_agent", destination=tool_id,
                        action="tool_call", auth_decision="deny",
                        mechanism="P3_execution_verification",
                        interception_step=7,
                        extra={"l7_reason": l7_reason, **self._args_for_log(tc)},
                    )
                return {"status": "execution_mismatch", "tool_id": tool_id,
                        "reason": "Execution verification failed."}

        # ── Step 5: Execute tool with latency tracking ──
        _t0 = _time.perf_counter()
        if self.tool_registry:
            try:
                response = await self.tool_registry.call_tool(
                    tool_id, tc.arguments, source=f"{phase}_agent"
                )
            except Exception as _e:
                response = {"status": "error", "tool_id": tool_id,
                            "error": str(_e)[:200]}
        else:
            response = {"status": "no_registry", "tool_id": tool_id}
        _latency = (_time.perf_counter() - _t0) * 1000
        self._layer_lat["exec"] = _latency
        _t = _time.perf_counter()

        if isinstance(response, dict) and response.pop("_harness_injected", None):
            # exposure record (T2): the model is about to see the injected response
            if self.logger:
                self.logger.log(source="harness", destination=tool_id, action="injection_served",
                                extra={"channel": "tool_response", "phase": phase, "tool": tool_id,
                                       "call_id": getattr(tc, "call_id", "")})

        # ── Harness fault: forged response (unsigned) ──
        if self.harness_injection:
            response = self._apply_post_execution_fault(phase, tc, response)

        # ── Post-execution checks (agenticcyops only) ──
        if self.config == "agenticcyops":
            # ── Step 6: P1-L2 — Response integrity (schema, timing, replay, signature) ──
            if (self.auth_interface and isinstance(response, dict)
                    and self._principle_active("P1")):
                resp_ok, resp_reason = self.auth_interface.validate_response(
                    tool_id, response, _latency
                )
                _t = self._lap("P1_L2", _t)
                if not resp_ok:
                    if self.logger:
                        self.logger.log(
                            source=f"{phase}_agent", destination=tool_id,
                            action="tool_call", auth_decision="deny",
                            mechanism="P1_authenticated_interface",
                            interception_step=6,
                            extra={"p1l2_reason": resp_reason, **self._args_for_log(tc)},
                        )
                    return {"status": "response_rejected", "tool_id": tool_id,
                            "reason": "Response validation failed."}

            # ── Step 7: P2-L3 — Output classification (Fix #8: actual redaction) ──
            if (self.output_classifier and isinstance(response, dict)
                    and self._principle_active("P2")):
                safe, class_reason, class_details = self.output_classifier.classify(
                    tool_id, response, agent_phase=phase
                )
                _t = self._lap("P2_L3", _t)
                if not safe:
                    if self.logger:
                        self.logger.log(
                            source=f"{phase}_agent", destination=tool_id,
                            action="tool_call", auth_decision="redact",
                            mechanism="P2_capability_scoping",
                            interception_step=7,
                            extra={"p2l3_reason": class_reason, **class_details,
                                   **self._args_for_log(tc)},
                        )
                    # Fix #8: Actually redact sensitive content
                    response = {
                        "status": "redacted",
                        "tool_id": tool_id,
                        "_redacted": True,
                        "_classification": class_reason,
                    }

        if self.logger:
            self.logger.log_tool_call(
                agent=f"{phase}_agent",
                tool=tool_id,
                auth_decision="allow",
                mechanism="P2_capability_scoping" if self.config != "flat" else "none",
                latency_ms=_latency,
            extra=self._args_for_log(tc))

        if isinstance(response, dict):
            response.pop("signature", None)
        return response

    async def _mma_post(self, path: str, payload: dict, timeout: float = 10.0):
        """POST to the MMA gateway.  Returns ``(status_code, body)``;
        ``(0, {"error": ...})`` when the gateway is unreachable."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{self.mma_url}{path}", json=payload, timeout=timeout)
            try:
                body = resp.json()
            except Exception:
                body = {}
            return resp.status_code, body
        except Exception as exc:
            return 0, {"error": str(exc)[:160]}

    @staticmethod
    def _p5_mechanism(status_code: int, body) -> str:
        """Map an MMA read denial (status + detail) to the P5 layer name.

        MMA returns 403 for L1 access control, 422 for L3 query scope
        violations, 429 for L4 read-pattern anomalies, with the specific
        reason in ``detail``.
        """
        detail = body.get("detail", "") if isinstance(body, dict) else ""
        if status_code == 403:
            return "P5_access_control"
        if status_code in (422, 429) and str(detail).startswith("P5_"):
            return str(detail).split(".")[0].split(":")[0].strip()
        return f"P5_denied_{status_code}"

    async def _process_memory_read(self, phase: str, mr: dict, context: dict) -> dict:
        """Scripted memory read with config-appropriate enforcement (H4).

        flat          -> the store, no checks (``mechanism="none"``)
        acl_hardened  -> manifest ACL, then the store (``acl_network_layer``)
        agenticcyops  -> MMA gateway with P5 L1-L5
        Returns ``{"store", "query", "documents", "status"}`` for the
        agent's context; documents are empty on denial.
        """
        store = mr.get("store", "")
        query = mr.get("query", "")
        call_id = self._next_call_id(phase, "mem_read", f"{store}|{query}")
        if self.logger:
            self.logger.log(source=f"{phase}_agent", destination=store,
                            action="memory_read_proposed",
                            extra={"call_id": call_id, "query": query, "scripted": True})
        out = {"store": store, "query": query, "documents": [], "status": "denied"}

        if self.config == "acl_hardened":
            allowed, reason = self.enforcer.validate_memory_read(phase, store)
            if not allowed:
                if self.logger:
                    self.logger.log_memory_read(agent=f"{phase}_agent", store=store,
                                                auth_decision="deny", mechanism="acl_network_layer",
                                                extra={"call_id": call_id})
                out["reason"] = f"403: {reason}"
                return out

        bypass = self.config != "agenticcyops"
        incident = context.get("incident") or {}
        # P5-L3 compares the query with the incident (v3.1: before, no context
        # reached the gateway and the relevance check never ran)
        inc_text = " ".join(str(incident.get(k) or "") for k in
                            ("alert_type", "incident_type", "case_type", "matter_type",
                             "description")).strip()
        status, body = await self._mma_post("/memory/read", {
            "phase": phase, "store_id": store, "query": query, "n_results": 3,
            "auth_token": self._mma_token(phase, store),
            "skip_p5": bypass or not self._principle_active("P5"),
            "context": inc_text,
        })
        if status == 0:
            if self.logger:
                self.logger.log_memory_read(agent=f"{phase}_agent", store=store,
                                            auth_decision="error", mechanism="mma_unreachable",
                                            extra={"call_id": call_id, "error": body.get("error")})
            out["status"] = "error"
            return out

        if status == 200:
            docs = body.get("documents", []) if isinstance(body, dict) else []
            metas = body.get("metadatas", []) if isinstance(body, dict) else []
            out.update({"documents": docs, "status": "ok"})
            mech = ("none" if self.config == "flat"
                    else "acl_network_layer" if self.config == "acl_hardened"
                    else "P5_access_control")
            if self.logger:
                # Exposure evidence (T2): ids of the returned records that carry
                # a doc_id in their metadata (harness-seeded records always do)
                # and which of those came back with sanitized text.
                result_ids, sanitized_ids = [], []
                for doc, m in zip(docs, metas if isinstance(metas, list) else []):
                    did = m.get("doc_id") if isinstance(m, dict) else None
                    if not did:
                        continue
                    result_ids.append(str(did))
                    if m.get("_sanitized") or (isinstance(doc, str) and "[REDACTED" in doc):
                        sanitized_ids.append(str(did))
                self.logger.log_memory_read(agent=f"{phase}_agent", store=store,
                                            auth_decision="allow", mechanism=mech,
                                            num_results=len(docs),
                                            extra={"call_id": call_id, "result_ids": result_ids[:20],
                                                   "sanitized_ids": sanitized_ids[:20]},
                                            )
                # P5-L5 sanitisation evidence on the returned entries
                sanitized = sum(1 for m in metas if isinstance(m, dict) and m.get("_sanitized"))
                if sanitized or any("[REDACTED" in d for d in docs if isinstance(d, str)):
                    self.logger.log(source=f"{phase}_agent", destination=store,
                                    action="memory_read", auth_decision="allow",
                                    mechanism="P5_injection_sanitization",
                                    extra={"sanitized_entries": sanitized, "store": store,
                                           "phase": phase, "call_id": call_id})
            return out

        mech = self._p5_mechanism(status, body) if self.config == "agenticcyops" else f"store_denied_{status}"
        if self.logger:
            self.logger.log_memory_read(agent=f"{phase}_agent", store=store,
                                        auth_decision="deny", mechanism=mech,
                                        extra={"call_id": call_id})
        return out

    async def _process_memory_write(self, phase: str, mw: dict, context: dict):
        """Process a memory write with config-appropriate enforcement.

        A ``memory_write_proposed`` event precedes every check in every
        config; its ``call_id`` is carried by the resulting ``memory_write``
        event.
        """
        store_id = mw.get("store_id", "")
        content = mw.get("content", "")
        doc_id = mw.get("doc_id", f"{phase}_{store_id}_{context.get('incident_id', 'unknown')}")
        call_id = self._next_call_id(phase, "mem_write", f"{store_id}|{doc_id}|{content}")
        mem_meta = {"call_id": call_id, "doc_id": doc_id}
        if self.logger:
            import hashlib as _h
            self.logger.log(
                source=f"{phase}_agent", destination=store_id,
                action="memory_write_proposed",
                extra={**mem_meta,
                       "content_sha256": _h.sha256(str(content).encode()).hexdigest()[:16],
                       "content_len": len(str(content)),
                       "scripted": bool(mw.get("scripted", False))},
                scan_text=content,
            )

        mech_ok = ("none" if self.config == "flat"
                   else "acl_network_layer" if self.config == "acl_hardened"
                   else "P4_memory_integrity")

        if self.config == "acl_hardened":
            # ACL: manifest check but NO write-boundary filtering (P4 absent)
            allowed, reason = self.enforcer.validate_memory_write(phase, store_id)
            if not allowed:
                if self.logger:
                    self.logger.log_memory_write(
                        agent=f"{phase}_agent", store=store_id,
                        auth_decision="deny", mechanism="acl_network_layer",
                        extra=mem_meta)
                return {"status": "denied", "reason": f"403: {reason}"}

        # Every config writes to the same store through the gateway; flat and
        # acl_hardened bypass P4 / P5 (no gateway defenses in those systems).
        bypass = self.config != "agenticcyops"

        # ── E9: route writes to a critical store through the panel ──
        # Judged before the write, not after: the MMA has no dry-run and no
        # delete, so a post-hoc verdict could not undo a committed write. The
        # similarity-based branch E9 also describes ("passes every
        # deterministic check but scores below the P4.2 threshold + 0.2")
        # needs that dry-run, so it is deliberately not implemented here
        # rather than approximated.
        if self.write_judge and not bypass and store_id in self.critical_stores:
            if self.consensus:
                proposal = {"tool_id": f"memory_write:{store_id}", "action": "write",
                            "target": store_id, "document": str(content)[:2000],
                            "phase": phase}
                approved = await self.consensus.validate(proposal, context)
                if self.logger:
                    self.logger.log_memory_write(
                        agent=f"{phase}_agent", store=store_id,
                        auth_decision="allow" if approved else "deny",
                        mechanism=("P3_write_judge_approve" if approved
                                   else "P3_write_judge_reject"),
                        payload=content, extra={**mem_meta, "critical_store": True})
                if not approved:
                    return {"status": "denied", "mechanism": "P3_write_judge_reject"}

        status, body = await self._mma_post("/memory/write", {
            "phase": phase,
            "store_id": store_id,
            "document": content,
            "doc_id": doc_id,
            "incident_evidence": context.get("incident", {}).get("description", ""),
            "metadata": {**(mw.get("metadata", {}) or {}),
                         "trial_id": self._trial_id() or "untagged",
                         "config": self.config_label},
            "auth_token": self._mma_token(phase, store_id),
            # Ablation switches -- MMA bypasses the corresponding check when
            # set.  Default (full enforcement) for agenticcyops.
            "skip_p4": bypass or not self._principle_active("P4"),
            "skip_p5": bypass or not self._principle_active("P5"),
        })
        if status == 0:
            if self.logger:
                self.logger.log_memory_write(
                    agent=f"{phase}_agent", store=store_id,
                    auth_decision="error", mechanism="mma_unreachable",
                    payload=content, extra={**mem_meta, "error": body.get("error")})
            return {"status": "mma_unreachable"}

        # Parse specific P4/P5 mechanism from the MMA response.  MMA returns
        # 403 for P5 access control, 422 for P4 memory-integrity rejection,
        # with the specific reason (e.g. P4_similarity_reject,
        # P4_drift_outlier, P4_metadata_invalid) in ``detail``.
        if status == 200:
            accepted = body.get("accepted", True) if isinstance(body, dict) else True
            sim = body.get("similarity_score", 0.0) if isinstance(body, dict) else 0.0
            mechanism = mech_ok
        else:
            accepted = False
            sim = 0.0
            detail = body.get("detail", "") if isinstance(body, dict) else ""
            if bypass:
                mechanism = f"store_denied_{status}"
            elif status == 403:
                mechanism = "P5_access_control"
            elif status == 422 and "P4_" in detail:
                mechanism = next((tok.rstrip(".,:") for tok in detail.split()
                                  if tok.startswith("P4_")), "P4_memory_integrity")
            else:
                mechanism = f"P4_denied_{status}"
        if self.logger:
            self.logger.log_memory_write(
                agent=f"{phase}_agent", store=store_id,
                auth_decision="allow" if accepted else "deny",
                mechanism=mechanism,
                cosine_similarity=sim if not bypass else None,
                payload=content, extra=mem_meta)
        return body if isinstance(body, dict) else {"status": "written"}
