"""
T8 - IAM/PAM Credential Manager.

Manages identity and privileged access: revoke, reset, or escalate
user credentials during incident response.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["revoke", "reset", "escalate"],
            "description": "Credential management action to perform.",
        },
        "target_user": {
            "type": "string",
            "description": "Username or principal to act upon.",
        },
        "reason": {
            "type": "string",
            "description": "Justification for the credential action.",
        },
        "incident_id": {
            "type": "string",
            "description": "Associated incident identifier.",
        },
    },
    "required": ["action", "target_user", "reason", "incident_id"],
}


async def handler(args: dict, state: dict) -> dict:
    action = args["action"]
    target_user = args["target_user"]
    reason = args["reason"]
    incident_id = args["incident_id"]

    # Initialise state-tracked list on first call
    if "revoked_users" not in state:
        state["revoked_users"] = []

    base = {
        "status": "success",
        "action_taken": action,
        "target_user": target_user,
        "incident_id": incident_id,
    }

    if action == "revoke":
        if target_user not in state["revoked_users"]:
            state["revoked_users"].append(target_user)
        base["message"] = (
            f"All active sessions and API keys for '{target_user}' have been "
            f"revoked. Reason: {reason}"
        )
        base["sessions_terminated"] = 3
        base["api_keys_revoked"] = 2

    elif action == "reset":
        base["message"] = (
            f"Password and MFA token for '{target_user}' have been reset. "
            f"A secure enrollment link was sent to the recovery address."
        )
        base["temporary_password_set"] = True
        base["mfa_reset"] = True
        base["enrollment_link_sent"] = True

    elif action == "escalate":
        base["message"] = (
            f"Privilege escalation request for '{target_user}' submitted for "
            f"approval. Incident {incident_id} attached."
        )
        base["approval_required"] = True
        base["approver_group"] = "security-ops-leads"
        base["escalation_ticket"] = f"ESC-{incident_id}-{target_user[:4].upper()}"

    else:
        base["status"] = "error"
        base["message"] = f"Unknown action: {action}"

    state["actions_log"].append(
        {"action": action, "target_user": target_user, "incident_id": incident_id}
    )

    return base


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T8_iam_pam",
        tool_name="IAM/PAM Credential Manager",
        description="Revoke, reset, or escalate user credentials during incident response.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
