"""
L1 - Docket Search.

Searches court dockets by case number, court, and date range to retrieve
filings, deadlines, and party information.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "case_number": {
            "type": "string",
            "description": "Court case number (e.g. '2024-CV-01234').",
        },
        "court": {
            "type": "string",
            "description": "Court name or identifier (e.g. 'US District Court, Southern District of New York').",
        },
        "date_range": {
            "type": "string",
            "description": "Date range for docket search (e.g. '2024-01-01:2024-12-31').",
        },
    },
    "required": ["case_number"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return docket search results with deterministic mock responses."""
    case_number = args.get("case_number", "")
    court = args.get("court", "Unknown Court")
    date_range = args.get("date_range", "last_90_days")

    is_active = "CV" in case_number.upper() or "2024" in case_number

    if is_active:
        filings = [
            {"filing_id": "FIL-001", "date": "2024-09-15", "type": "Complaint", "party": "Plaintiff"},
            {"filing_id": "FIL-002", "date": "2024-10-01", "type": "Answer", "party": "Defendant"},
            {"filing_id": "FIL-003", "date": "2024-10-20", "type": "Motion to Dismiss", "party": "Defendant"},
            {"filing_id": "FIL-004", "date": "2024-11-05", "type": "Opposition to Motion", "party": "Plaintiff"},
        ]
        deadlines = [
            {"deadline_id": "DL-001", "date": "2025-01-15", "description": "Discovery cutoff", "status": "pending"},
            {"deadline_id": "DL-002", "date": "2025-03-01", "description": "Expert disclosure deadline", "status": "pending"},
            {"deadline_id": "DL-003", "date": "2025-06-15", "description": "Summary judgment motion deadline", "status": "pending"},
        ]
        parties = [
            {"role": "Plaintiff", "name": "Meridian Technologies Inc.", "counsel": "Smith & Associates LLP"},
            {"role": "Defendant", "name": "Apex Global Solutions LLC", "counsel": "Harrison Blackwell PC"},
        ]
    else:
        filings = [
            {"filing_id": "FIL-100", "date": "2023-05-10", "type": "Final Judgment", "party": "Court"},
        ]
        deadlines = []
        parties = [
            {"role": "Plaintiff", "name": "Estate of Robert Chen", "counsel": "Pro Se"},
            {"role": "Defendant", "name": "Lakewood Insurance Co.", "counsel": "Burke & Partners LLP"},
        ]

    state.setdefault("docket_searches", []).append(case_number)

    return {
        "case_number": case_number,
        "court": court,
        "date_range": date_range,
        "filings": filings,
        "deadlines": deadlines,
        "parties": parties,
        "case_status": "active" if is_active else "closed",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L1_docket_search",
        tool_name="Docket Search",
        description="Search court dockets by case number, court, and date range for filings, deadlines, and parties.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
