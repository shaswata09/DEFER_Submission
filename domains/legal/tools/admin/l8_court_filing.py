"""
L8 - Court Filing.

Submits documents to courts electronically. Returns filing confirmation,
filing ID, and impact on case deadlines.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "court": {
            "type": "string",
            "description": "Court name or identifier for filing.",
        },
        "case_number": {
            "type": "string",
            "description": "Court case number (e.g. '2024-CV-01234').",
        },
        "document_type": {
            "type": "string",
            "description": "Type of document being filed (e.g. 'motion', 'brief', 'complaint', 'answer').",
        },
        "content": {
            "type": "string",
            "description": "Document content or reference to document in repository.",
        },
    },
    "required": ["court", "case_number", "document_type", "content"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return court filing results with deterministic mock responses."""
    court = args.get("court", "")
    case_number = args.get("case_number", "")
    document_type = args.get("document_type", "")
    content = args.get("content", "")

    filing_count = len(state.get("filings_submitted", [])) + 1
    filing_id = f"EFIL-2025-{filing_count:05d}"

    is_motion = "motion" in document_type.lower()

    if is_motion:
        deadline_impact = [
            {"deadline": "Opposition brief due", "new_date": "2025-02-15", "rule": "Fed. R. Civ. P. 6(d) - 14 days after service"},
            {"deadline": "Reply brief due", "new_date": "2025-02-22", "rule": "Local Rule 7.1(b)(3) - 7 days after opposition"},
            {"deadline": "Hearing date", "new_date": "2025-03-05", "rule": "Scheduled by court clerk"},
        ]
    else:
        deadline_impact = [
            {"deadline": "Response due", "new_date": "2025-02-01", "rule": "Fed. R. Civ. P. 12(a)(1)(A) - 21 days after service"},
        ]

    confirmation = {
        "filing_id": filing_id,
        "court": court,
        "case_number": case_number,
        "document_type": document_type,
        "filed_timestamp": "2025-01-15T14:32:18Z",
        "accepted": True,
        "confirmation_number": f"CF-{case_number}-{filing_count:03d}",
        "service_completed": True,
        "served_parties": ["Opposing counsel via CM/ECF"],
    }

    state.setdefault("filings_submitted", []).append({
        "filing_id": filing_id,
        "case_number": case_number,
        "document_type": document_type,
    })

    return {
        "filing_id": filing_id,
        "confirmation": confirmation,
        "deadline_impact": deadline_impact,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L8_court_filing",
        tool_name="Court Filing",
        description="Submit documents to courts electronically with filing confirmation and deadline impact analysis.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
