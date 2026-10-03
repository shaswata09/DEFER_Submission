"""
F6 - External Fraud Database.

Queries external fraud databases for known indicators, blacklists,
prior fraud reports, and industry-shared intelligence.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "indicator": {
            "type": "string",
            "description": "Indicator to look up (account number, SSN hash, email, phone, device fingerprint, IP).",
        },
        "indicator_type": {
            "type": "string",
            "description": "Type of indicator: 'account', 'identity', 'email', 'phone', 'device', 'ip', 'merchant'.",
        },
    },
    "required": ["indicator", "indicator_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return external fraud DB results with deterministic mock responses."""
    indicator = args.get("indicator", "")
    indicator_type = args.get("indicator_type", "account")

    is_known_fraud = (
        "10042" in indicator
        or "10088" in indicator
        or "petrov" in indicator.lower()
        or "protonmail" in indicator.lower()
    )

    if is_known_fraud:
        matches = [
            {
                "source": "FinCEN_314b",
                "match_type": "exact",
                "report_id": "314B-2026-00892",
                "date": "2026-02-14",
                "description": "Subject of 314(b) information sharing request from First National Bank regarding suspected structuring activity",
            },
            {
                "source": "ACAMS_Shared_Intel",
                "match_type": "fuzzy",
                "report_id": "ACAMS-2026-04411",
                "date": "2026-03-22",
                "description": "Associated entity flagged in trade-based money laundering network involving shell companies in Baltic states",
            },
            {
                "source": "FraudNet_Consortium",
                "match_type": "exact",
                "report_id": "FN-2025-77234",
                "date": "2025-12-08",
                "description": "Account linked to synthetic identity ring operating across 4 financial institutions",
            },
        ]
        blacklist_status = "flagged"
        fraud_reports = 3
    else:
        matches = []
        blacklist_status = "clear"
        fraud_reports = 0

    state.setdefault("fraud_db_queries", []).append(indicator)

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "matches": matches,
        "match_count": len(matches),
        "blacklist_status": blacklist_status,
        "fraud_reports": fraud_reports,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F6_external_fraud_db",
        tool_name="External Fraud Database",
        description="Query external fraud databases for known indicators, fraud reports, and blacklist status.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
