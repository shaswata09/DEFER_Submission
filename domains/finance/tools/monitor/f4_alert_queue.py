"""
F4 - Alert Queue.

Creates, updates, or escalates fraud alerts with priority and assignment tracking.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["create", "update", "escalate"],
            "description": "Action to perform on the alert queue.",
        },
        "alert_data": {
            "type": "object",
            "description": "Alert details: alert_id (for update/escalate), account_id, description, risk_score, etc.",
        },
    },
    "required": ["action", "alert_data"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return alert queue response with deterministic mock responses."""
    action = args.get("action", "create")
    alert_data = args.get("alert_data", {})

    alert_id = alert_data.get("alert_id", f"ALT-2026-{len(state.get('alerts', [])) + 5001:05d}")
    risk_score = alert_data.get("risk_score", 50)

    if risk_score >= 80:
        priority = "P1-critical"
        assigned_to = "Senior Fraud Analyst - Team Lead"
        sla_minutes = 30
    elif risk_score >= 60:
        priority = "P2-high"
        assigned_to = "Fraud Analyst L2"
        sla_minutes = 120
    elif risk_score >= 40:
        priority = "P3-medium"
        assigned_to = "Fraud Analyst L1"
        sla_minutes = 480
    else:
        priority = "P4-low"
        assigned_to = "Auto-monitoring Queue"
        sla_minutes = 1440

    if action == "escalate":
        priority = "P1-critical"
        assigned_to = "BSA Officer / Fraud Investigation Unit"
        sla_minutes = 15

    state.setdefault("alerts", []).append({
        "alert_id": alert_id,
        "action": action,
    })

    return {
        "alert_id": alert_id,
        "action": action,
        "priority": priority,
        "assigned_to": assigned_to,
        "sla_minutes": sla_minutes,
        "status": "open" if action == "create" else "updated" if action == "update" else "escalated",
        "timestamp": "2026-04-09T14:30:00Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F4_alert_queue",
        tool_name="Alert Queue",
        description="Create, update, or escalate fraud alerts with priority and assignment tracking.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
