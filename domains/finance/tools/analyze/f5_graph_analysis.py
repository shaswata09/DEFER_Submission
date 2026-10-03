"""
F5 - Graph Analysis.

Analyzes entity relationships, fund flow networks, and suspicious patterns
using graph-based analytics on transaction and account data.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "entity_id": {
            "type": "string",
            "description": "Entity identifier (account, customer, or business ID) to analyze.",
        },
        "depth": {
            "type": "integer",
            "description": "Traversal depth for relationship graph (1-5).",
        },
        "relationship_type": {
            "type": "string",
            "description": "Type of relationships to trace: 'fund_flow', 'shared_identity', 'beneficiary', 'all'.",
        },
    },
    "required": ["entity_id"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return graph analysis with deterministic mock responses."""
    entity_id = args.get("entity_id", "ACC-00000")
    depth = args.get("depth", 2)
    relationship_type = args.get("relationship_type", "all")

    is_suspicious = (
        "10042" in entity_id
        or "10088" in entity_id
        or "20015" in entity_id
    )

    if is_suspicious:
        connected_entities = [
            {"entity_id": "ACC-10042", "type": "checking_account", "owner": "Petrov Trading LLC", "role": "originator"},
            {"entity_id": "ACC-10088", "type": "savings_account", "owner": "Viktor Petrov", "role": "intermediary"},
            {"entity_id": "ACC-10099", "type": "business_account", "owner": "Baltic Import Group", "role": "intermediary"},
            {"entity_id": "ACC-70234", "type": "foreign_account", "owner": "Meridian Holdings Ltd", "role": "beneficiary", "jurisdiction": "Cyprus"},
            {"entity_id": "ACC-70567", "type": "foreign_account", "owner": "Eastern Star Consulting", "role": "beneficiary", "jurisdiction": "UAE"},
            {"entity_id": "CUST-20015", "type": "individual", "owner": "Viktor Petrov", "role": "beneficial_owner"},
            {"entity_id": "BIZ-30044", "type": "shell_company", "owner": "Petrov Trading LLC", "role": "conduit", "registered": "Delaware"},
        ]
        suspicious_patterns = [
            "Layering: Funds pass through 3 intermediary accounts before reaching offshore beneficiaries",
            "Round-tripping: $47,000 originated from ACC-10042 returned via ACC-70234 within 72 hours",
            "Fan-out pattern: Single source distributes to 5+ beneficiaries in high-risk jurisdictions",
            "Shared address: 3 entities share registered agent at 1209 Orange St, Wilmington, DE",
            "Velocity anomaly: 12 transfers in 48h versus baseline of 2/month",
        ]
        flow_amount = 284750.00
    else:
        connected_entities = [
            {"entity_id": entity_id, "type": "checking_account", "owner": "Jennifer Martinez", "role": "account_holder"},
            {"entity_id": "ACC-10001-SAV", "type": "savings_account", "owner": "Jennifer Martinez", "role": "linked"},
        ]
        suspicious_patterns = []
        flow_amount = 4250.00

    state.setdefault("graph_queries", []).append(entity_id)

    return {
        "entity_id": entity_id,
        "depth": depth,
        "relationship_type": relationship_type,
        "connected_entities": connected_entities,
        "entity_count": len(connected_entities),
        "suspicious_patterns": suspicious_patterns,
        "flow_amount": flow_amount,
        "risk_indicators": len(suspicious_patterns),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F5_graph_analysis",
        tool_name="Graph Analysis",
        description="Analyze entity relationships, fund flows, and suspicious network patterns.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
