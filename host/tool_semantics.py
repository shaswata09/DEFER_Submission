"""What each state-changing tool acts on, in one place.

The orchestrator (proposal hoisting), the parameter validator (P2.2 target,
criticality and wildcard checks) and the cross-incident ledger (P3.4) all need
to know a tool's action and target. Before defense-freeze-v3.2 each kept its own
partial map: L8's target was mapped to a field its schema does not have, and the
admin tools of finance, healthcare and legal that take no ``action`` argument
were invisible to the ledger and the destructive-action rules.
"""
from __future__ import annotations

# v3.1: the admin tools of healthcare, finance and legal do one thing each and
# take no ``action`` argument, so every P3 check keyed on (tool, action) --
# time policy, change conflict, impacts, dangerous patterns -- missed them.
IMPLIED_ACTION = {
    "F8_account_freeze": "freeze", "F9_chargeback_processor": "process",
    "F10_wire_recall": "recall", "H8_prescription_writer": "prescribe",
    "H9_procedure_scheduler": "schedule", "H10_insurance_preauth": "submit",
    "L8_court_filing": "file", "L9_document_signing": "sign",
    "L10_payment_processing": "disburse",
}

# the argument that names what a tool acts on, for checks that read ``target``
TARGET_ARGS = ("target", "target_user", "target_host", "account_id", "patient_id",
               "case_number", "case_id", "wire_id", "transaction_id", "matter_id",
               "document_id")

# the state-changing tools and the argument that holds their target, taken from
# the tool schemas (domains/*/tools/admin/*.py)
TARGET_FIELDS = {
    "T8_iam_pam": "target_user",
    "T9_firewall": "target",
    "T10_config_manager": "target_host",
    "T11_epp_av": "target",
    "T12_ansible": "target_hosts",
    "F8_account_freeze": "account_id",
    "F9_chargeback_processor": "transaction_id",
    "F10_wire_recall": "wire_id",
    "H8_prescription_writer": "patient_id",
    "H9_procedure_scheduler": "patient_id",
    "H10_insurance_preauth": "patient_id",
    "L8_court_filing": "case_number",
    "L9_document_signing": "document_id",
    "L10_payment_processing": "matter_id",
}

# arguments whose value scopes what a call touches; a wildcard there widens the
# blast radius, while "all" in, say, a lab-test selector is an ordinary value
SCOPE_ARGS = tuple(dict.fromkeys(TARGET_ARGS + tuple(TARGET_FIELDS.values()) + (
    "target_hosts", "target_users", "targets", "hosts", "users", "accounts",
    "scope", "signers", "entity_id", "indicator")))


def action_of(tool_id: str, arguments: dict, proposal: dict | None = None) -> str:
    """The action a call performs: the hoisted or explicit ``action``, else the
    tool's implied one."""
    for src in (proposal or {}, arguments or {}):
        a = src.get("action")
        if a:
            return str(a).lower()
    return IMPLIED_ACTION.get(tool_id, "")


def target_of(tool_id: str, arguments: dict):
    """The value a state-changing call acts on, or ``None``."""
    arguments = arguments or {}
    field = TARGET_FIELDS.get(tool_id)
    if field and field in arguments:
        return arguments[field]
    return arguments.get("target")
