"""
F13 - Regulatory Submission.

Submits filings to regulatory authorities including FinCEN, OCC,
CFPB, and state regulators with tracking and confirmation.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "filing_type": {
            "type": "string",
            "description": "Type of filing: 'sar', 'ctr', 'ofac_report', 'reg_e_notice', 'consent_order_response', 'exam_response'.",
        },
        "data": {
            "type": "object",
            "description": "Filing data payload including form fields, narratives, and supporting documentation references.",
        },
        "authority": {
            "type": "string",
            "description": "Regulatory authority: 'fincen', 'occ', 'cfpb', 'fdic', 'fed_reserve', 'state_dfs'.",
        },
    },
    "required": ["filing_type", "data", "authority"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return regulatory submission result with deterministic mock responses."""
    filing_type = args.get("filing_type", "sar")
    data = args.get("data", {})
    authority = args.get("authority", "fincen")

    submission_id = f"SUB-2026-{len(state.get('submissions', [])) + 6001:05d}"

    if filing_type in ("sar", "ctr"):
        status = "submitted_pending_acknowledgment"
        confirmation = f"BSA E-Filing confirmation pending; batch ID BSAEF-{submission_id}"
        retention_years = 5
    elif filing_type == "ofac_report":
        status = "submitted"
        confirmation = f"OFAC voluntary self-disclosure acknowledged; reference OFAC-VSD-{submission_id}"
        retention_years = 5
    else:
        status = "submitted"
        confirmation = f"Filing received by {authority.upper()}; tracking reference {authority.upper()}-{submission_id}"
        retention_years = 7

    state.setdefault("submissions", []).append({
        "submission_id": submission_id,
        "filing_type": filing_type,
        "authority": authority,
    })

    return {
        "submission_id": submission_id,
        "filing_type": filing_type,
        "authority": authority,
        "status": status,
        "confirmation": confirmation,
        "timestamp": "2026-04-09T15:00:00Z",
        "retention_period_years": retention_years,
        "next_action": "Monitor for acknowledgment" if "pending" in status else "Archive confirmation",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F13_regulatory_submission",
        tool_name="Regulatory Submission",
        description="Submit filings to regulatory authorities (FinCEN, OCC, CFPB) with tracking.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
