"""
P1-P5 Framework-Agnostic Middleware for the TAMAS benchmark.

Wraps arbitrary agent tool calls and memory operations with the full
DEFER defense pipeline.  Unlike :class:`SOARHost` which assumes a
fixed 4-phase pipeline (monitor / analyze / admin / report), this
middleware treats each agent ROLE as an independent actor and evaluates
defenses on a per-call basis.

Usage::

    from benchmarks._unused_tamas.middleware import P12345Middleware

    role_manifests = {
        "DiagnosisAgent": {
            "allowed_tools": ["read_ehr", "run_diagnostic_test"],
            "allowed_memory_read": ["patient_history"],
            "allowed_memory_write": ["diagnosis_notes"],
            "requires_consensus": False,
            "escalation_triggers": {
                "bulk_action_threshold": 10,
                "critical_tools": ["prescribe_medication"],
            },
        },
    }

    mw = P12345Middleware(role_manifests=role_manifests)

    # Before executing a tool
    ok, details = await mw.check_tool_call(
        role="DiagnosisAgent",
        tool_id="read_ehr",
        arguments={"patient_id": "P001"},
        context={"task_evidence": "Patient P001 reports chest pain"},
    )

    # After execution
    safe, reason = mw.classify_output("read_ehr", response, role="DiagnosisAgent")

    # Memory operations
    ok, _ = await mw.check_memory_write(role, store_id, content, metadata, context)
    ok, _ = mw.check_memory_read(role, store_id, query, context)
"""

from typing import Any, Optional

from logging_utils import ExperimentLogger

from host.authenticated_interface import AuthenticatedInterface
from host.parameter_validator import ParameterValidator
from host.output_classifier import OutputClassifier
from consensus.verified_execution import VerifiedExecution
from consensus.validator import ConsensusValidator
from memory.memory_integrity import MemoryIntegrity
from memory.access_isolation import AccessIsolation

from benchmarks._unused_tamas.middleware.role_manifest import DynamicManifestEnforcer


class _RoleAccessController:
    """Duck-typed :class:`AccessController` that reads ACLs from role manifests.

    :class:`memory.access_isolation.AccessIsolation` only needs the
    three methods below from its injected controller, so we avoid
    requiring a real ``access_policy.json`` file for TAMAS.
    """

    def __init__(self, role_manifests: dict):
        self.role_manifests: dict = role_manifests or {}

    def can_read(self, role: str, store_id: str) -> bool:
        manifest = self.role_manifests.get(role, {})
        return store_id in manifest.get("allowed_memory_read", [])

    def can_write(self, role: str, store_id: str) -> bool:
        manifest = self.role_manifests.get(role, {})
        return store_id in manifest.get("allowed_memory_write", [])

    def accessible_stores(self, role: str, mode: str = "read") -> list:
        manifest = self.role_manifests.get(role, {})
        return list(manifest.get(f"allowed_memory_{mode}", []))


class P12345Middleware:
    """Framework-agnostic P1-P5 enforcement wrapper.

    Instantiates every defense component used by :class:`SOARHost` but
    exposes them through a role-oriented API instead of a phase-oriented
    one.  Intended to be used as a thin pre/post-call wrapper around
    arbitrary TAMAS agent frameworks (AutoGen, CrewAI, etc.).
    """

    # ------------------------------------------------------------------ #
    #  Construction
    # ------------------------------------------------------------------ #

    def __init__(
        self,
        role_manifests: dict,
        consensus_validator: Optional[ConsensusValidator] = None,
        embedding_model=None,
        logger: Optional[ExperimentLogger] = None,
        domain: str = "tamas",
    ):
        """
        Args:
            role_manifests: ``{role_name: manifest_dict}`` -- see
                :class:`DynamicManifestEnforcer` for the expected format.
            consensus_validator: Optional :class:`ConsensusValidator`.
                If ``None`` P3's LLM-consensus layer (L6) is skipped,
                but every other P3 safety gate still runs.
            embedding_model: Optional SentenceTransformer-compatible
                model used by P2-L2 (target-in-evidence), P2-L3
                (sensitive categories), P4 drift, and P5 diversity.
            logger: Optional :class:`ExperimentLogger` for structured logs.
            domain: Domain identifier used to resolve config files under
                ``domains/{domain}/configs/``.  Defaults to ``"tamas"``.
        """
        self.domain = domain
        self.logger = logger
        self.role_manifests = role_manifests or {}

        # ---- P1: Authenticated Interface ---------------------------------
        self.auth = AuthenticatedInterface(domain=domain, logger=logger)

        # ---- P2: Capability Scoping --------------------------------------
        #  L1 -- dynamic role-based manifest enforcer
        self.enforcer = DynamicManifestEnforcer(
            role_manifests=self.role_manifests, logger=logger
        )
        #  L2 -- parameter validator
        self.param_validator = ParameterValidator(
            domain=domain,
            embedding_model=embedding_model,
            logger=logger,
        )
        #  L3 -- output classifier
        self.output_classifier = OutputClassifier(
            domain=domain,
            embedding_model=embedding_model,
            logger=logger,
        )

        # ---- P3: Verified Execution --------------------------------------
        self.consensus = consensus_validator
        self.p3 = VerifiedExecution(
            domain=domain,
            consensus_validator=self.consensus,
            embedding_model=embedding_model,
            logger=logger,
        )

        # ---- P4: Memory Integrity ----------------------------------------
        self.p4 = MemoryIntegrity(
            domain=domain,
            embedding_model=embedding_model,
            logger=logger,
        )

        # ---- P5: Access-Controlled Isolation -----------------------------
        #  Inject a duck-typed controller that reads ACLs from role manifests
        #  so AccessIsolation does not require a domain access_policy.json.
        self._access_controller = _RoleAccessController(self.role_manifests)
        self.p5 = AccessIsolation(
            domain=domain,
            access_controller=self._access_controller,
            embedding_model=embedding_model,
            logger=logger,
        )

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _log_deny(
        self,
        role: str,
        target: str,
        mechanism: str,
        step: int,
        extra: Optional[dict] = None,
    ) -> None:
        """Structured deny log (mirrors SOARHost patterns)."""
        if self.logger is None:
            return
        self.logger.log(
            source=f"{role}_agent",
            destination=target,
            action="tool_call",
            auth_decision="deny",
            mechanism=mechanism,
            interception_step=step,
            extra=extra or {},
        )

    # ------------------------------------------------------------------ #
    #  Tool call pipeline: P1-L1 -> P2-L1 -> P2-L2 -> P3
    # ------------------------------------------------------------------ #

    async def check_tool_call(
        self,
        role: str,
        tool_id: str,
        arguments: dict,
        context: dict,
    ) -> tuple[bool, dict]:
        """Run the full pre-execution P1/P2/P3 pipeline for a tool call.

        Args:
            role: The calling agent's role.
            tool_id: Identifier of the tool being invoked.
            arguments: The proposed tool arguments.
            context: Task context.  Recognised keys:

                - ``task_evidence`` (str): reference text used by
                  P2-L2 target-in-evidence and P3 adaptive consent.
                - ``task_id`` (str): incident-id equivalent for P3.
                - ``justification`` (str): optional justification text
                  passed through to P3 layers.

        Returns:
            ``(allowed, details)`` where ``details`` always contains
            either ``{"approved": True}`` or a dict describing the
            defense that rejected the call.
        """
        arguments = arguments or {}
        context = context or {}

        # ---- P1-L1: Component identity ------------------------------------
        ok, reason = self.auth.verify_component(tool_id, "tools")
        if not ok:
            # TAMAS tools live outside component_registry.json; we tolerate
            # unregistered tools but hard-fail any other P1 reason.
            if "P1_unregistered" in reason:
                if self.logger:
                    self.logger.log(
                        source="middleware",
                        destination=tool_id,
                        action="P1_L1_verify",
                        auth_decision="allow",
                        mechanism="P1_tamas_unregistered_allowed",
                    )
            else:
                self._log_deny(role, tool_id, "P1_authenticated_interface", 1,
                               {"reason": reason})
                return False, {
                    "mechanism": "P1_authenticated_interface",
                    "reason": reason,
                    "step": 1,
                }

        # ---- P2-L1: Role-based manifest check -----------------------------
        ok, reason = self.enforcer.validate_tool_call(role, tool_id)
        if not ok:
            self._log_deny(role, tool_id, "P2_capability_scoping", 2,
                           {"reason": reason})
            return False, {
                "mechanism": "P2_capability_scoping",
                "reason": reason,
                "step": 2,
            }

        # ---- P2-L2: Parameter validation ----------------------------------
        task_evidence = context.get("task_evidence", "")
        params_ok, p_reason, p_details = self.param_validator.validate(
            tool_id, arguments, task_evidence
        )
        if not params_ok:
            self._log_deny(role, tool_id, "P2_capability_scoping", 2,
                           {"p2l2_reason": p_reason, **p_details})
            return False, {
                "mechanism": "P2_capability_scoping",
                "reason": p_reason,
                "details": p_details,
                "step": 2,
            }

        # ---- P3: Verified Execution (only when required) ------------------
        if self.enforcer.requires_consensus(role, tool_id):
            proposal = {
                "tool_id": tool_id,
                "arguments": dict(arguments),
                "role": role,
                # P3 internals are phase-oriented; map role -> phase.
                "phase": role,
                "justification": context.get("justification", ""),
            }
            # Hoist argument fields to the top level for P3 layers that
            # read action/target from the proposal root (mirrors SOARHost).
            for field in (
                "action", "target", "target_user", "target_hosts",
                "target_users", "account_id", "patient_id", "case_id",
            ):
                if field in arguments and field not in proposal:
                    proposal[field] = arguments[field]

            p3_context = {
                **context,
                "current_phase": role,
                "incident_id": context.get("task_id", "tamas"),
            }
            approved = await self.p3.validate(proposal, p3_context)
            if not approved:
                self._log_deny(role, tool_id, "P3_verified_execution", 3)
                return False, {
                    "mechanism": "P3_verified_execution",
                    "step": 3,
                }

        # ---- Bulk action check --------------------------------------------
        self.enforcer.record_action(role)
        count = self.enforcer._action_counts.get(role, 0)
        if self.enforcer.check_bulk_action(role, count):
            self._log_deny(role, tool_id, "bulk_action_threshold", 3,
                           {"count": count})
            return False, {
                "mechanism": "bulk_action_threshold",
                "step": 3,
                "count": count,
            }

        return True, {"approved": True}

    # ------------------------------------------------------------------ #
    #  Post-execution hooks
    # ------------------------------------------------------------------ #

    def classify_output(
        self,
        tool_id: str,
        response: Any,
        role: str,
    ) -> tuple[bool, str]:
        """P2-L3: classify a tool response for sensitive content.

        Returns ``(safe, reason)`` where ``safe=True`` means the response
        is OK to propagate to the calling agent.
        """
        if not isinstance(response, dict):
            response = {"result": str(response)}
        safe, reason, _details = self.output_classifier.classify(
            tool_id, response, agent_phase=role
        )
        return safe, reason

    def verify_response(
        self,
        tool_id: str,
        response: Any,
        latency_ms: float,
    ) -> tuple[bool, str]:
        """P1-L2: validate response schema, timing, and replay hash."""
        if not isinstance(response, dict):
            response = {"result": str(response)}
        return self.auth.validate_response(tool_id, response, latency_ms)

    # ------------------------------------------------------------------ #
    #  Memory pipeline
    # ------------------------------------------------------------------ #

    async def check_memory_write(
        self,
        role: str,
        store_id: str,
        content: str,
        metadata: dict,
        context: dict,
    ) -> tuple[bool, dict]:
        """P5-L1 access check + full P4 integrity pipeline for memory writes.

        Returns ``(allowed, details)``.
        """
        metadata = metadata or {}
        context = context or {}

        # ---- P5-L1: role can write here? ----------------------------------
        ok, reason = self.enforcer.validate_memory_write(role, store_id)
        if not ok:
            if self.logger:
                if hasattr(self.logger, "log_memory_write"):
                    self.logger.log_memory_write(
                        agent=f"{role}_agent",
                        store=store_id,
                        auth_decision="deny",
                        mechanism="P5_access_control",
                    )
                else:
                    self.logger.log(
                        source=f"{role}_agent",
                        destination=store_id,
                        action="memory_write",
                        auth_decision="deny",
                        mechanism="P5_access_control",
                        extra={"reason": reason},
                    )
            return False, {
                "mechanism": "P5_access_control",
                "reason": reason,
            }

        # ---- P4: full memory integrity pipeline ---------------------------
        ok, p_reason, p_details = self.p4.validate_write(
            store_id=store_id,
            content=content,
            metadata=metadata,
            incident_evidence=context.get("task_evidence", ""),
        )
        if not ok:
            if self.logger:
                self.logger.log(
                    source=f"{role}_agent",
                    destination=store_id,
                    action="memory_write",
                    auth_decision="deny",
                    mechanism="P4_memory_integrity",
                    extra={"p4_reason": p_reason, **p_details},
                )
            return False, {
                "mechanism": "P4_memory_integrity",
                "reason": p_reason,
                "details": p_details,
            }

        return True, {"approved": True, "details": p_details}

    def check_memory_read(
        self,
        role: str,
        store_id: str,
        query: str,
        context: dict,
    ) -> tuple[bool, dict]:
        """P5 memory read: access (L1) + query scope (L3) + read pattern (L4).

        Returns ``(allowed, details)``.
        """
        context = context or {}

        # ---- P5-L1: role can read here? -----------------------------------
        ok, reason = self.enforcer.validate_memory_read(role, store_id)
        if not ok:
            if self.logger:
                self.logger.log(
                    source=f"{role}_agent",
                    destination=store_id,
                    action="memory_read",
                    auth_decision="deny",
                    mechanism="P5_access_control",
                    extra={"reason": reason},
                )
            return False, {
                "mechanism": "P5_access_control",
                "reason": reason,
            }

        # ---- P5-L3: query scope ------------------------------------------
        task_evidence = context.get("task_evidence", "")
        ok, reason, details = self.p5.validate_query(
            role, store_id, query, task_evidence
        )
        if not ok:
            return False, {
                "mechanism": "P5_query_scope",
                "reason": reason,
                "details": details,
            }

        # ---- P5-L4: read pattern -----------------------------------------
        ok, reason, details = self.p5.check_read_pattern(role, store_id, query)
        if not ok:
            return False, {
                "mechanism": "P5_read_pattern",
                "reason": reason,
                "details": details,
            }

        return True, {"approved": True}

    def sanitize_read_results(self, results: list, role: str) -> list:
        """P5-L5: strip prompt-injection patterns from memory read results."""
        return self.p5.sanitize_results(results, role)

    def filter_read_fields(
        self,
        role: str,
        store_id: str,
        results: list,
    ) -> list:
        """P5-L2: field-level redaction / summary-only truncation."""
        return self.p5.filter_fields(role, store_id, results)

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def reset_for_task(self) -> None:
        """Reset per-task state (equivalent to per-incident reset in SOARHost)."""
        self.enforcer.reset_counts()
        if self.p3 is not None:
            self.p3.reset_for_incident()
        if self.auth is not None:
            self.auth.reset_replay_cache()
