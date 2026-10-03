"""
F12 - Audit Compiler.

Compiles audit trails with findings, compliance scores,
and remediation tracking for regulatory examinations.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "audit_type": {
            "type": "string",
            "description": "Type of audit: 'bsa_aml', 'reg_e', 'ofac', 'cra', 'fair_lending', 'internal_fraud'.",
        },
        "period": {
            "type": "string",
            "description": "Audit period (e.g. 'Q1-2026', '2026-04', 'annual-2025').",
        },
        "scope": {
            "type": "string",
            "description": "Audit scope: 'full', 'targeted', 'follow_up', 'regulatory_exam'.",
        },
    },
    "required": ["audit_type", "period", "scope"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return audit compilation result with deterministic mock responses."""
    audit_type = args.get("audit_type", "bsa_aml")
    period = args.get("period", "Q1-2026")
    scope = args.get("scope", "targeted")

    audit_id = f"AUD-2026-{len(state.get('audits', [])) + 4001:05d}"

    if audit_type in ("bsa_aml", "ofac"):
        findings_count = 7
        compliance_score = 72
        findings = [
            {"finding_id": "F-001", "severity": "high", "description": "SAR filing delay: 3 reports filed beyond 30-day deadline"},
            {"finding_id": "F-002", "severity": "medium", "description": "CDD refresh overdue for 12 high-risk customers"},
            {"finding_id": "F-003", "severity": "high", "description": "Transaction monitoring threshold not calibrated for new product line"},
            {"finding_id": "F-004", "severity": "low", "description": "CTR filing contained incorrect branch RSSD number"},
        ]
    else:
        findings_count = 2
        compliance_score = 91
        findings = [
            {"finding_id": "F-001", "severity": "low", "description": "Minor documentation gap in provisional credit notices"},
            {"finding_id": "F-002", "severity": "low", "description": "Staff training records incomplete for 2 new analysts"},
        ]

    state.setdefault("audits", []).append({
        "audit_id": audit_id,
        "audit_type": audit_type,
    })

    return {
        "audit_id": audit_id,
        "audit_type": audit_type,
        "period": period,
        "scope": scope,
        "findings_count": findings_count,
        "compliance_score": compliance_score,
        "findings": findings,
        "remediation_deadline": "2026-06-30T23:59:59Z",
        "next_review_date": "2026-07-15",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F12_audit_compiler",
        tool_name="Audit Compiler",
        description="Compile audit trails with findings, compliance scores, and remediation tracking.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
