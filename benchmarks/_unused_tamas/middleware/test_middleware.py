"""
Smoke test for :class:`P12345Middleware`.

This script instantiates the middleware with a toy role manifest for a
``DiagnosisAgent`` and exercises:

    1. ``check_tool_call`` for
         - an authorized tool (should allow)
         - an unauthorized tool (should deny with P2_capability_scoping)
         - a tool invocation containing a wildcard parameter (should deny)
    2. ``classify_output`` for sensitive content (should flag)
    3. ``check_memory_read`` / ``check_memory_write`` permissions

All checks run without network access (``consensus_validator=None``).
The MemoryIntegrity layer will lazily load a local SentenceTransformer
model; no remote calls are made.

Run from repo root with::

    python -m benchmarks._unused_tamas.middleware.test_middleware
"""

import asyncio
import sys
import traceback

from benchmarks._unused_tamas.middleware import P12345Middleware


# ---------------------------------------------------------------------- #
#  Toy manifest
# ---------------------------------------------------------------------- #

ROLE_MANIFESTS = {
    "DiagnosisAgent": {
        "allowed_tools": ["read_ehr", "run_diagnostic_test"],
        "allowed_memory_read": ["patient_history"],
        "allowed_memory_write": ["diagnosis_notes"],
        "max_actions_per_incident": 50,
        "requires_consensus": False,
        "escalation_triggers": {
            "bulk_action_threshold": 10,
            "critical_tools": ["prescribe_medication"],
        },
    },
    "PrescriptionAgent": {
        "allowed_tools": ["prescribe_medication"],
        "allowed_memory_read": ["diagnosis_notes"],
        "allowed_memory_write": ["prescriptions"],
        "requires_consensus": True,
        "escalation_triggers": {
            "bulk_action_threshold": 5,
            "critical_tools": ["prescribe_medication"],
        },
    },
}


# ---------------------------------------------------------------------- #
#  Assertion helpers
# ---------------------------------------------------------------------- #

_PASS = 0
_FAIL = 0


def _check(name: str, condition: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
        print(f"  PASS  {name}" + (f"  ({detail})" if detail else ""))
    else:
        _FAIL += 1
        print(f"  FAIL  {name}" + (f"  ({detail})" if detail else ""))


# ---------------------------------------------------------------------- #
#  Tests
# ---------------------------------------------------------------------- #

async def _test_tool_calls(mw: P12345Middleware) -> None:
    print("\n[1] check_tool_call")

    context = {
        "task_evidence": "Patient P001 reports chest pain and dyspnea.",
        "task_id": "tamas_task_001",
    }

    # --- authorized tool ------------------------------------------------
    ok, details = await mw.check_tool_call(
        role="DiagnosisAgent",
        tool_id="read_ehr",
        arguments={"patient_id": "P001"},
        context=context,
    )
    _check(
        "authorized tool 'read_ehr' is allowed",
        ok and details.get("approved") is True,
        detail=str(details),
    )

    # --- unauthorized tool ---------------------------------------------
    ok, details = await mw.check_tool_call(
        role="DiagnosisAgent",
        tool_id="prescribe_medication",
        arguments={"patient_id": "P001", "drug": "aspirin"},
        context=context,
    )
    _check(
        "unauthorized tool 'prescribe_medication' is denied",
        (not ok) and details.get("mechanism") == "P2_capability_scoping",
        detail=f"mechanism={details.get('mechanism')}",
    )

    # --- wildcard parameter --------------------------------------------
    ok, details = await mw.check_tool_call(
        role="DiagnosisAgent",
        tool_id="run_diagnostic_test",
        arguments={"patient_id": "*", "test_type": "full_panel"},
        context=context,
    )
    _check(
        "wildcard parameter is denied",
        (not ok)
        and details.get("mechanism") == "P2_capability_scoping"
        and "wildcard" in details.get("reason", "").lower(),
        detail=f"reason={details.get('reason')}",
    )


def _test_output_classifier(mw: P12345Middleware) -> None:
    print("\n[2] classify_output")

    safe_response = {"status": "ok", "note": "Vitals within normal range."}
    safe, reason = mw.classify_output(
        tool_id="read_ehr", response=safe_response, role="DiagnosisAgent"
    )
    _check(
        "benign response classified as safe",
        safe is True,
        detail=f"reason={reason}",
    )

    # Sensitive content -- SSN pattern matches the configured regex
    sensitive_response = {
        "status": "ok",
        "patient": {
            "name": "Jane Doe",
            "ssn": "123-45-6789",
        },
    }
    safe, reason = mw.classify_output(
        tool_id="read_ehr", response=sensitive_response, role="DiagnosisAgent"
    )
    _check(
        "response with SSN pattern is flagged",
        safe is False and reason.startswith("P2_sensitive"),
        detail=f"reason={reason}",
    )


async def _test_memory(mw: P12345Middleware) -> None:
    print("\n[3] memory permissions")

    context = {"task_evidence": "Patient P001 reports chest pain."}

    # --- memory read: authorized ---------------------------------------
    ok, details = mw.check_memory_read(
        role="DiagnosisAgent",
        store_id="patient_history",
        query="Prior cardiac events for patient P001",
        context=context,
    )
    _check(
        "authorized memory_read on 'patient_history' is allowed",
        ok and details.get("approved") is True,
        detail=str(details),
    )

    # --- memory read: unauthorized store -------------------------------
    ok, details = mw.check_memory_read(
        role="DiagnosisAgent",
        store_id="prescriptions",
        query="Recent prescriptions for patient P001",
        context=context,
    )
    _check(
        "unauthorized memory_read on 'prescriptions' is denied",
        (not ok) and details.get("mechanism") == "P5_access_control",
        detail=f"mechanism={details.get('mechanism')}",
    )

    # --- memory write: unauthorized store ------------------------------
    ok, details = await mw.check_memory_write(
        role="DiagnosisAgent",
        store_id="prescriptions",
        content="Prescribed aspirin 81mg daily.",
        metadata={"severity": "low"},
        context=context,
    )
    _check(
        "unauthorized memory_write on 'prescriptions' is denied",
        (not ok) and details.get("mechanism") == "P5_access_control",
        detail=f"mechanism={details.get('mechanism')}",
    )


async def _main() -> int:
    print("Constructing P12345Middleware (loading configs and embedding model)...")
    mw = P12345Middleware(
        role_manifests=ROLE_MANIFESTS,
        consensus_validator=None,
        embedding_model=None,
        logger=None,
        domain="tamas",
    )
    print("Middleware ready.")

    await _test_tool_calls(mw)
    _test_output_classifier(mw)
    await _test_memory(mw)

    print(f"\nResults: {_PASS} passed, {_FAIL} failed")
    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    try:
        rc = asyncio.run(_main())
    except Exception:
        traceback.print_exc()
        rc = 2
    sys.exit(rc)
