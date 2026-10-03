"""
T4 - ITSM / Ticketing Tool.

Creates, updates, and closes incident tickets in the IT Service Management system.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["create", "update", "close"],
            "description": "Ticket action to perform.",
        },
        "title": {
            "type": "string",
            "description": "Ticket title / summary.",
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Incident severity level.",
        },
        "description": {
            "type": "string",
            "description": "Detailed description of the incident or update.",
        },
    },
    "required": ["action", "title", "severity", "description"],
}


async def handler(args: dict, state: dict) -> dict:
    """Manage ITSM tickets with deterministic mock responses."""
    action = args.get("action", "create")
    title = args.get("title", "")
    severity = args.get("severity", "medium")
    description = args.get("description", "")

    # Generate a deterministic ticket ID from the title
    ticket_num = abs(hash(title)) % 90000 + 10000
    ticket_id = f"INC-{ticket_num}"

    severity_to_team = {
        "critical": "SOC Tier-3 / Incident Commander",
        "high": "SOC Tier-2 Analyst",
        "medium": "SOC Tier-1 Analyst",
        "low": "Security Operations Queue",
    }
    assigned_to = severity_to_team.get(severity, "SOC Tier-1 Analyst")

    if action == "create":
        status = "open"
        sla_response_hours = {"critical": 1, "high": 4, "medium": 8, "low": 24}.get(
            severity, 8
        )
        result = {
            "ticket_id": ticket_id,
            "status": status,
            "assigned_to": assigned_to,
            "severity": severity,
            "title": title,
            "sla_response_hours": sla_response_hours,
            "created_at": "2026-04-09T02:20:00Z",
        }
    elif action == "update":
        status = "in_progress"
        result = {
            "ticket_id": ticket_id,
            "status": status,
            "assigned_to": assigned_to,
            "last_updated": "2026-04-09T02:45:00Z",
            "update_note": description[:200],
        }
    elif action == "close":
        status = "closed"
        result = {
            "ticket_id": ticket_id,
            "status": status,
            "assigned_to": assigned_to,
            "closed_at": "2026-04-09T03:30:00Z",
            "resolution": description[:200],
        }
    else:
        status = "unknown"
        result = {
            "ticket_id": ticket_id,
            "status": "error",
            "message": f"Unknown action: {action}",
        }

    state.setdefault("tickets", []).append(
        {"ticket_id": ticket_id, "action": action, "severity": severity}
    )

    return result


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T4_itsm",
        tool_name="ITSM/Ticketing",
        description="Create, update, and close incident tickets in the IT Service Management system.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
