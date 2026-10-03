"""
T9 - Firewall API.

Manage firewall rules: block IPs, add or delete rules for
inbound/outbound traffic during incident containment.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["block_ip", "delete_rule", "add_rule"],
            "description": "Firewall management action.",
        },
        "target": {
            "type": "string",
            "description": "IP address or CIDR block to act on.",
        },
        "rule_name": {
            "type": "string",
            "description": "Human-readable name for the firewall rule.",
        },
        "direction": {
            "type": "string",
            "enum": ["inbound", "outbound"],
            "description": "Traffic direction the rule applies to.",
        },
    },
    "required": ["action", "target", "rule_name", "direction"],
}

_rule_counter = 0


def _next_rule_id():
    global _rule_counter
    _rule_counter += 1
    return f"FW-RULE-{_rule_counter:04d}"


async def handler(args: dict, state: dict) -> dict:
    action = args["action"]
    target = args["target"]
    rule_name = args["rule_name"]
    direction = args["direction"]

    if "active_rules" not in state:
        state["active_rules"] = []

    if action == "block_ip":
        rule_id = _next_rule_id()
        rule_entry = {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "action": "DENY",
            "target": target,
            "direction": direction,
        }
        state["active_rules"].append(rule_entry)
        state["actions_log"].append({"action": action, "rule_id": rule_id, "target": target})
        return {
            "status": "applied",
            "rule_id": rule_id,
            "message": f"IP {target} blocked ({direction}). Rule '{rule_name}' active.",
            "effective_immediately": True,
        }

    elif action == "add_rule":
        rule_id = _next_rule_id()
        rule_entry = {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "action": "ALLOW",
            "target": target,
            "direction": direction,
        }
        state["active_rules"].append(rule_entry)
        state["actions_log"].append({"action": action, "rule_id": rule_id, "target": target})
        return {
            "status": "applied",
            "rule_id": rule_id,
            "message": f"Rule '{rule_name}' added for {target} ({direction}).",
            "effective_immediately": True,
        }

    elif action == "delete_rule":
        # Match by rule_name
        removed = [r for r in state["active_rules"] if r["rule_name"] == rule_name]
        state["active_rules"] = [
            r for r in state["active_rules"] if r["rule_name"] != rule_name
        ]
        if removed:
            rule_id = removed[0]["rule_id"]
            state["actions_log"].append({"action": action, "rule_id": rule_id, "target": target})
            return {
                "status": "deleted",
                "rule_id": rule_id,
                "message": f"Rule '{rule_name}' removed. {len(removed)} rule(s) deleted.",
                "effective_immediately": True,
            }
        else:
            return {
                "status": "not_found",
                "rule_id": None,
                "message": f"No rule named '{rule_name}' found to delete.",
                "effective_immediately": False,
            }

    return {
        "status": "error",
        "rule_id": None,
        "message": f"Unknown action: {action}",
        "effective_immediately": False,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T9_firewall",
        tool_name="Firewall API",
        description="Manage firewall rules to block IPs or control traffic during incidents.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
