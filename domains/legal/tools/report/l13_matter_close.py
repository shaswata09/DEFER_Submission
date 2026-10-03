"""
L13 - Matter Close.

Executes matter closure procedures including final disposition recording,
document archiving, and retention scheduling.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "matter_id": {
            "type": "string",
            "description": "Matter identifier (e.g. 'MAT-001').",
        },
        "disposition": {
            "type": "string",
            "description": "Final matter disposition: 'settled', 'judgment_plaintiff', 'judgment_defendant', 'dismissed', 'withdrawn', 'transferred'.",
        },
        "final_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of final actions to perform (e.g. 'return_client_documents', 'close_trust_account', 'send_closing_letter').",
        },
    },
    "required": ["matter_id", "disposition", "final_actions"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return matter closure results with deterministic mock responses."""
    matter_id = args.get("matter_id", "")
    disposition = args.get("disposition", "settled")
    final_actions = args.get("final_actions", [])

    closure_count = len(state.get("matters_closed", [])) + 1
    closure_id = f"CLS-2025-{closure_count:05d}"

    action_results = []
    for action in final_actions:
        action_results.append({
            "action": action,
            "status": "completed",
            "completed_at": "2025-01-15T18:00:00Z",
        })

    archive_reference = {
        "archive_id": f"ARC-{matter_id}",
        "location": "Secure Document Vault - Shelf 14B",
        "digital_archive": f"s3://firm-archive/matters/{matter_id}/",
        "retention_period": "7 years",
        "destruction_date": "2032-01-15",
        "retention_policy": "Firm Policy RP-2024-001 - General Litigation",
    }

    state.setdefault("matters_closed", []).append({
        "closure_id": closure_id,
        "matter_id": matter_id,
        "disposition": disposition,
    })

    return {
        "closure_id": closure_id,
        "matter_id": matter_id,
        "disposition": disposition,
        "status": "closed",
        "final_action_results": action_results,
        "archive_reference": archive_reference,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L13_matter_close",
        tool_name="Matter Close",
        description="Execute matter closure procedures including disposition, archiving, and retention scheduling.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
