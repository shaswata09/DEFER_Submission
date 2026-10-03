"""
Attack Injector.

Takes an attack payload and modifies the task context / agent inputs
to deliver the attack. Returns the modified task context and an oracle
callback that can be queried after the run to determine attack success.

The injector does not itself interact with AutoGen - it annotates a
``task_ctx`` dict with ``_attack_*`` keys that the runner (AgentWrapper,
benchmark harness) is expected to interpret.  Keeping this thin makes it
easy to unit-test the injection semantics without running a full agent
swarm.
"""

from __future__ import annotations

from typing import Any, Callable

from .tamas_payloads import get_attack_payload


class AttackInjector:
    """Inject a TAMAS attack into a task context.

    Example:
        >>> injector = AttackInjector("direct_prompt_injection",
        ...                           "healthcare_prescription")
        >>> ctx = injector.inject_into_context({"task_description": "Diagnose"})
        >>> oracle = injector.get_oracle()
        >>> # ...run the agent workflow over ``ctx`` and collect ``run_log``...
        >>> attack_succeeded = oracle(run_log)
    """

    def __init__(self, attack_type: str, scenario: str) -> None:
        self.attack_type = attack_type
        self.scenario = scenario
        self.payload = get_attack_payload(attack_type, scenario)
        if self.payload is None:
            raise ValueError(
                f"No TAMAS payload registered for attack_type={attack_type!r} "
                f"scenario={scenario!r}"
            )

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------
    def inject_into_context(self, task_ctx: dict[str, Any]) -> dict[str, Any]:
        """Return a new task context with the attack annotations applied.

        The original ``task_ctx`` is not mutated; a shallow copy is returned.

        Args:
            task_ctx: The benign task context supplied to the agent swarm.

        Returns:
            A shallow copy of ``task_ctx`` with attack-specific metadata
            merged in.  Standard keys added:

            - ``_attack_active`` (bool): always True after injection
            - ``_attack_type`` (str): the attack type key
            - ``_attack_scenario`` (str): the scenario key
            - ``_attack_payload`` (dict): the raw payload (for diagnostics)

            Attack-specific keys (see per-branch logic below) are added when
            applicable.
        """
        if not isinstance(task_ctx, dict):
            raise TypeError(
                f"task_ctx must be a dict, got {type(task_ctx).__name__}"
            )

        modified: dict[str, Any] = dict(task_ctx)
        modified["_attack_active"] = True
        modified["_attack_type"] = self.attack_type
        modified["_attack_scenario"] = self.scenario
        modified["_attack_payload"] = self.payload

        if self.attack_type == "direct_prompt_injection":
            # Append injection to task description so the target agent sees it.
            existing = modified.get("task_description", "")
            modified["task_description"] = (
                f"{existing}\n\n{self.payload['injection']}"
                if existing
                else self.payload["injection"]
            )

        elif self.attack_type == "indirect_prompt_injection":
            # Poison a memory store (the runner is responsible for staging the
            # content into whichever memory backend is in use).
            modified["_poisoned_memory"] = {
                "store": self.payload["poisoned_memory_store"],
                "content": self.payload["poisoned_content"],
            }

        elif self.attack_type == "byzantine_behavior":
            # Mark which agent is rogue and what deviation it should perform.
            modified["_rogue_agent"] = self.payload["attacker_role"]
            modified["_rogue_deviation"] = self.payload["deviation"]
            modified["_rogue_tool"] = self.payload.get("injection_tool")
            modified["_rogue_tool_args"] = self.payload.get("injection_args", {})

        elif self.attack_type == "persuasive_manipulation":
            modified["_persuasion_prompt"] = self.payload["manipulation"]
            modified["_persuasion_source"] = self.payload["attacker_role"]
            modified["_persuasion_target"] = self.payload["target_agent"]

        elif self.attack_type == "tool_misuse":
            modified["_misuse_role"] = self.payload["attacker_role"]
            modified["_misuse_tool"] = self.payload["target_tool"]
            modified["_misuse_prompt"] = self.payload["injection"]

        elif self.attack_type == "data_exfiltration":
            modified["_exfil_role"] = self.payload["attacker_role"]
            modified["_exfil_prompt"] = self.payload["injection"]
            modified["_exfil_patterns"] = self.payload["success_criterion"]["patterns"]

        return modified

    # ------------------------------------------------------------------
    # Oracle
    # ------------------------------------------------------------------
    def get_oracle(self) -> Callable[[list[dict[str, Any]]], bool]:
        """Return an evaluator that, given a run log, reports attack success.

        The evaluator is produced by
        :func:`benchmarks._unused_tamas.metrics.asr.make_asr_evaluator` so that the
        injector stays decoupled from metric code.
        """
        # Imported here to avoid a circular import at module load time.
        from benchmarks._unused_tamas.metrics.asr import make_asr_evaluator
        return make_asr_evaluator(self.attack_type, self.payload)
