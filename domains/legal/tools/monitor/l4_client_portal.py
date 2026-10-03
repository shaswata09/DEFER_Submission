"""
L4 - Client Portal.

Manages client communications including messages, document uploads,
and matter status updates through the secure client portal.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "client_id": {
            "type": "string",
            "description": "Client identifier (e.g. 'CLT-001').",
        },
        "action": {
            "type": "string",
            "enum": ["message", "upload", "status"],
            "description": "Portal action: send message, upload document, or check status.",
        },
    },
    "required": ["client_id", "action"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return client portal results with deterministic mock responses."""
    client_id = args.get("client_id", "")
    action = args.get("action", "status")

    communication_log = [
        {"date": "2024-12-20", "type": "message", "direction": "outbound", "subject": "Case status update - December"},
        {"date": "2024-12-28", "type": "upload", "direction": "inbound", "subject": "Signed retainer agreement"},
        {"date": "2025-01-02", "type": "message", "direction": "inbound", "subject": "Question regarding discovery timeline"},
    ]

    pending_items = [
        {"item_id": "PI-001", "type": "document_request", "description": "Signed authorization for medical records", "requested_date": "2024-12-15", "status": "pending"},
        {"item_id": "PI-002", "type": "payment", "description": "Retainer replenishment - $5,000", "requested_date": "2025-01-02", "status": "pending"},
    ]

    if action == "message":
        result_message = f"Message queued for delivery to client {client_id}."
    elif action == "upload":
        result_message = f"Document upload initiated for client {client_id}."
    else:
        result_message = f"Status retrieved for client {client_id}."

    state.setdefault("portal_actions", []).append({"client_id": client_id, "action": action})

    return {
        "client_id": client_id,
        "action": action,
        "communication_log": communication_log,
        "pending_items": pending_items,
        "result_message": result_message,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L4_client_portal",
        tool_name="Client Portal",
        description="Manage client communications, document uploads, and status updates through the secure portal.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
