"""
F8 - Account Freeze.

Freezes accounts to prevent further unauthorized transactions.
Supports full freeze, debit-only freeze, and wire-hold modes.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "account_id": {
            "type": "string",
            "description": "Account identifier to freeze (e.g. ACC-10042).",
        },
        "reason": {
            "type": "string",
            "description": "Reason for freeze: 'fraud_confirmed', 'fraud_suspected', 'aml_hold', 'regulatory_order', 'customer_request'.",
        },
        "duration": {
            "type": "string",
            "description": "Freeze duration: '24h', '72h', '30d', 'indefinite', 'pending_investigation'.",
        },
    },
    "required": ["account_id", "reason", "duration"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return account freeze result with deterministic mock responses."""
    account_id = args.get("account_id", "ACC-00000")
    reason = args.get("reason", "fraud_suspected")
    duration = args.get("duration", "pending_investigation")

    freeze_id = f"FRZ-2026-{len(state.get('freezes', [])) + 7001:05d}"

    affected_services = ["debit_card", "wire_transfers", "ach_origination", "online_banking", "bill_pay"]
    if reason == "customer_request":
        affected_services = ["debit_card", "online_banking"]

    state.setdefault("freezes", []).append({
        "freeze_id": freeze_id,
        "account_id": account_id,
        "reason": reason,
    })

    return {
        "freeze_id": freeze_id,
        "account_id": account_id,
        "reason": reason,
        "duration": duration,
        "effective_time": "2026-04-09T14:30:00Z",
        "affected_services": affected_services,
        "status": "active",
        "requires_bsa_notification": reason in ("fraud_confirmed", "aml_hold", "regulatory_order"),
        "customer_notification_sent": reason != "regulatory_order",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F8_account_freeze",
        tool_name="Account Freeze",
        description="Freeze accounts to prevent further unauthorized transactions.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
