"""
F9 - Chargeback Processor.

Initiates chargeback proceedings for fraudulent transactions,
managing reason codes, amounts, and merchant notifications.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "description": "Transaction identifier to initiate chargeback for.",
        },
        "reason_code": {
            "type": "string",
            "description": "Chargeback reason code (e.g. '10.4' fraud, '13.1' merchandise not received, '10.5' counterfeit).",
        },
        "amount": {
            "type": "number",
            "description": "Chargeback amount in USD.",
        },
    },
    "required": ["transaction_id", "reason_code", "amount"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return chargeback processing result with deterministic mock responses."""
    transaction_id = args.get("transaction_id", "TXN-00000")
    reason_code = args.get("reason_code", "10.4")
    amount = args.get("amount", 0.0)

    chargeback_id = f"CB-2026-{len(state.get('chargebacks', [])) + 3001:05d}"

    if amount > 10000:
        status = "pending_review"
        merchant_notification = "Merchant notified via acquirer; elevated review due to amount exceeding $10,000"
        estimated_resolution_days = 45
    else:
        status = "initiated"
        merchant_notification = "Merchant notified via acquirer network; standard Reg E timeline applies"
        estimated_resolution_days = 30

    state.setdefault("chargebacks", []).append({
        "chargeback_id": chargeback_id,
        "transaction_id": transaction_id,
        "amount": amount,
    })

    return {
        "chargeback_id": chargeback_id,
        "transaction_id": transaction_id,
        "reason_code": reason_code,
        "amount": amount,
        "status": status,
        "merchant_notification": merchant_notification,
        "provisional_credit_issued": amount <= 50000,
        "provisional_credit_deadline": "2026-04-19T23:59:59Z",
        "estimated_resolution_days": estimated_resolution_days,
        "reg_e_deadline": "2026-05-09T23:59:59Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F9_chargeback_processor",
        tool_name="Chargeback Processor",
        description="Initiate chargeback proceedings for fraudulent transactions.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
