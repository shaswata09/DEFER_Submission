"""
F11 - SAR Generator.

Generates Suspicious Activity Report narratives and prepares
FinCEN SAR/CTR filings with proper regulatory formatting.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {
            "type": "string",
            "description": "Investigation case identifier.",
        },
        "suspicious_activity": {
            "type": "string",
            "description": "Description of suspicious activity type: 'structuring', 'money_laundering', 'account_takeover', 'wire_fraud', 'identity_fraud', 'insider_abuse'.",
        },
        "amount": {
            "type": "number",
            "description": "Total amount involved in suspicious activity (USD).",
        },
    },
    "required": ["case_id", "suspicious_activity", "amount"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return SAR generation result with deterministic mock responses."""
    case_id = args.get("case_id", "CASE-00000")
    suspicious_activity = args.get("suspicious_activity", "structuring")
    amount = args.get("amount", 0.0)

    sar_id = f"SAR-2026-{len(state.get('sars', [])) + 10001:05d}"

    filing_deadline = "2026-05-09T23:59:59Z"  # 30 days from activity detection

    if amount >= 100000:
        priority = "expedited"
        filing_status = "draft_pending_bsa_officer_review"
    else:
        priority = "standard"
        filing_status = "draft_generated"

    state.setdefault("sars", []).append({
        "sar_id": sar_id,
        "case_id": case_id,
        "amount": amount,
    })

    return {
        "sar_id": sar_id,
        "case_id": case_id,
        "suspicious_activity": suspicious_activity,
        "amount": amount,
        "filing_status": filing_status,
        "priority": priority,
        "deadline": filing_deadline,
        "fincen_form": "FinCEN Form 111" if suspicious_activity != "ctr_required" else "FinCEN Form 112",
        "narrative_sections": [
            "Subject Information",
            "Suspicious Activity Description",
            "Transaction Details",
            "Relationship to Financial Institution",
            "Law Enforcement Contact Information",
        ],
        "retention_period_years": 5,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F11_sar_generator",
        tool_name="SAR Generator",
        description="Generate SAR narratives and prepare FinCEN CTR/SAR filings.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
