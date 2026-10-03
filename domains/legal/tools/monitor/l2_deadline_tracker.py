"""
L2 - Deadline Tracker.

Tracks, sets, and manages litigation and transactional deadlines for matters.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "matter_id": {
            "type": "string",
            "description": "Internal matter identifier (e.g. 'MAT-001').",
        },
        "action": {
            "type": "string",
            "enum": ["check", "set", "dismiss"],
            "description": "Action to perform: check existing deadlines, set a new one, or dismiss.",
        },
    },
    "required": ["matter_id", "action"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return deadline tracking results with deterministic mock responses."""
    matter_id = args.get("matter_id", "")
    action = args.get("action", "check")

    upcoming_deadlines = [
        {"deadline_id": "DL-2001", "matter_id": matter_id, "date": "2025-01-10", "description": "Response to interrogatories due", "priority": "high", "days_remaining": 12},
        {"deadline_id": "DL-2002", "matter_id": matter_id, "date": "2025-01-25", "description": "Deposition of key witness", "priority": "medium", "days_remaining": 27},
        {"deadline_id": "DL-2003", "matter_id": matter_id, "date": "2025-02-14", "description": "Mediation session scheduled", "priority": "medium", "days_remaining": 47},
    ]

    overdue_items = []
    if "001" in matter_id or "005" in matter_id:
        overdue_items = [
            {"deadline_id": "DL-1999", "matter_id": matter_id, "date": "2024-12-15", "description": "Document production deadline", "days_overdue": 14, "escalation_status": "attorney_notified"},
        ]

    if action == "set":
        result_message = f"New deadline created for matter {matter_id}."
    elif action == "dismiss":
        result_message = f"Deadline dismissed for matter {matter_id}. Audit trail updated."
    else:
        result_message = f"Deadline check completed for matter {matter_id}."

    state.setdefault("deadline_actions", []).append({"matter_id": matter_id, "action": action})

    return {
        "matter_id": matter_id,
        "action": action,
        "upcoming_deadlines": upcoming_deadlines,
        "overdue_items": overdue_items,
        "result_message": result_message,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L2_deadline_tracker",
        tool_name="Deadline Tracker",
        description="Track, set, or dismiss litigation and transactional deadlines for matters.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
