"""
F10 - Wire Recall.

Initiates wire transfer recall requests to intercept and recover
funds from fraudulent wire transactions via SWIFT/Fedwire channels.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "wire_id": {
            "type": "string",
            "description": "Wire transfer identifier to recall.",
        },
        "reason": {
            "type": "string",
            "description": "Reason for recall: 'fraud', 'unauthorized', 'erroneous', 'sanctions_match', 'court_order'.",
        },
        "urgency": {
            "type": "string",
            "description": "Urgency level: 'immediate', 'same_day', 'standard'.",
        },
    },
    "required": ["wire_id", "reason", "urgency"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return wire recall result with deterministic mock responses."""
    wire_id = args.get("wire_id", "WIRE-00000")
    reason = args.get("reason", "fraud")
    urgency = args.get("urgency", "immediate")

    recall_id = f"RCL-2026-{len(state.get('recalls', [])) + 1001:05d}"

    if urgency == "immediate":
        status = "swift_mt192_sent"
        estimated_recovery = "Funds hold requested at beneficiary bank; response expected within 24-48 hours"
    elif urgency == "same_day":
        status = "recall_queued"
        estimated_recovery = "Recall message queued for next Fedwire processing window"
    else:
        status = "recall_initiated"
        estimated_recovery = "Standard recall process initiated; 5-10 business day recovery timeline"

    state.setdefault("recalls", []).append({
        "recall_id": recall_id,
        "wire_id": wire_id,
        "reason": reason,
    })

    return {
        "recall_id": recall_id,
        "wire_id": wire_id,
        "reason": reason,
        "urgency": urgency,
        "status": status,
        "estimated_recovery": estimated_recovery,
        "swift_reference": f"SWIFT-{recall_id}",
        "beneficiary_bank_notified": urgency == "immediate",
        "law_enforcement_referral": reason in ("fraud", "sanctions_match", "court_order"),
        "recovery_probability": 0.72 if urgency == "immediate" else 0.45 if urgency == "same_day" else 0.23,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F10_wire_recall",
        tool_name="Wire Recall",
        description="Initiate wire transfer recall requests for intercepting fraudulent wires.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
