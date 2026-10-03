"""
T10 - Configuration Manager.

Push or rollback configuration changes on target hosts during
incident remediation and hardening.
"""

import hashlib
import json

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["push", "rollback"],
            "description": "Configuration action to perform.",
        },
        "target_host": {
            "type": "string",
            "description": "Hostname or IP of the target system.",
        },
        "config_change": {
            "type": "object",
            "description": "Key-value pairs representing the configuration delta.",
        },
    },
    "required": ["action", "target_host", "config_change"],
}


async def handler(args: dict, state: dict) -> dict:
    action = args["action"]
    target_host = args["target_host"]
    config_change = args.get("config_change", {})

    if "config_history" not in state:
        state["config_history"] = []

    change_hash = hashlib.sha256(
        json.dumps(config_change, sort_keys=True, default=str).encode()
    ).hexdigest()[:10]

    if action == "push":
        entry = {
            "change_id": f"CFG-{change_hash}",
            "target_host": target_host,
            "config_change": config_change,
            "rolled_back": False,
        }
        state["config_history"].append(entry)
        state["actions_log"].append({"action": "push", "change_id": entry["change_id"]})

        diff_lines = [f"+ {k}: {v}" for k, v in config_change.items()]

        return {
            "status": "applied",
            "change_id": entry["change_id"],
            "target_host": target_host,
            "diff": "\n".join(diff_lines),
            "rollback_available": True,
            "message": (
                f"Configuration pushed to {target_host}. "
                f"{len(config_change)} parameter(s) updated."
            ),
        }

    elif action == "rollback":
        # Rollback the most recent un-rolled-back entry for this host
        candidates = [
            e for e in reversed(state["config_history"])
            if e["target_host"] == target_host and not e["rolled_back"]
        ]
        if candidates:
            entry = candidates[0]
            entry["rolled_back"] = True
            state["actions_log"].append(
                {"action": "rollback", "change_id": entry["change_id"]}
            )

            diff_lines = [f"- {k}: {v}" for k, v in entry["config_change"].items()]

            return {
                "status": "rolled_back",
                "change_id": entry["change_id"],
                "target_host": target_host,
                "diff": "\n".join(diff_lines),
                "rollback_available": False,
                "message": (
                    f"Rolled back change {entry['change_id']} on {target_host}."
                ),
            }
        else:
            return {
                "status": "no_changes",
                "change_id": None,
                "target_host": target_host,
                "diff": "",
                "rollback_available": False,
                "message": f"No rollback-eligible changes found for {target_host}.",
            }

    return {
        "status": "error",
        "change_id": None,
        "target_host": target_host,
        "diff": "",
        "rollback_available": False,
        "message": f"Unknown action: {action}",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T10_config_manager",
        tool_name="Configuration Manager",
        description="Push or rollback configuration changes on target hosts.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
