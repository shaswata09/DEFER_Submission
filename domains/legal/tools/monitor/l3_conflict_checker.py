"""
L3 - Conflict Checker.

Checks for conflicts of interest by searching party names and matter types
against the firm's existing client and matter database.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "party_names": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of party names to check for conflicts.",
        },
        "matter_type": {
            "type": "string",
            "description": "Type of matter (e.g. 'litigation', 'corporate', 'real_estate').",
        },
    },
    "required": ["party_names"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return conflict check results with deterministic mock responses."""
    party_names = args.get("party_names", [])
    matter_type = args.get("matter_type", "general")

    has_conflict = any(
        "apex" in name.lower() or "globaltech" in name.lower()
        for name in party_names
    )

    if has_conflict:
        conflicts_found = True
        conflicting_matters = [
            {
                "matter_id": "MAT-042",
                "matter_name": "Apex Global Solutions v. Pinnacle Industries",
                "relationship": "Current client - adverse party",
                "attorney": "J. Harrison",
                "status": "active",
            },
        ]
        clearance_status = "blocked"
    else:
        conflicts_found = False
        conflicting_matters = []
        clearance_status = "cleared"

    state.setdefault("conflict_checks", []).append({
        "party_names": party_names,
        "result": clearance_status,
    })

    return {
        "party_names": party_names,
        "matter_type": matter_type,
        "conflicts_found": conflicts_found,
        "conflicting_matters": conflicting_matters,
        "clearance_status": clearance_status,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L3_conflict_checker",
        tool_name="Conflict Checker",
        description="Check for conflicts of interest against party names and matter types.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
