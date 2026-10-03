"""
L10 - Payment Processing.

Processes legal payments including trust account disbursements, vendor
payments, and court fees. Maintains trust account compliance.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "matter_id": {
            "type": "string",
            "description": "Matter identifier for payment association (e.g. 'MAT-001').",
        },
        "amount": {
            "type": "number",
            "description": "Payment amount in USD.",
        },
        "payee": {
            "type": "string",
            "description": "Payment recipient name or entity.",
        },
        "type": {
            "type": "string",
            "description": "Payment type: 'trust_disbursement', 'operating', 'court_fee', 'settlement', 'vendor'.",
        },
    },
    "required": ["matter_id", "amount", "payee", "type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return payment processing results with deterministic mock responses."""
    matter_id = args.get("matter_id", "")
    amount = args.get("amount", 0)
    payee = args.get("payee", "")
    payment_type = args.get("type", "operating")

    payment_count = len(state.get("payments_processed", [])) + 1
    payment_id = f"PAY-2025-{payment_count:05d}"

    is_trust = payment_type == "trust_disbursement" or payment_type == "settlement"

    if is_trust:
        prior_balance = 50000.00
        trust_account_balance = prior_balance - amount
        account_type = "IOLTA Trust Account"
        compliance_check = {
            "three_way_reconciliation": "passed",
            "client_authorization": "on_file",
            "bar_rule_compliance": "Rule 1.15 - satisfied",
        }
    else:
        prior_balance = None
        trust_account_balance = None
        account_type = "Operating Account"
        compliance_check = {
            "authorization": "approved",
            "budget_check": "within_budget",
        }

    state.setdefault("payments_processed", []).append({
        "payment_id": payment_id,
        "matter_id": matter_id,
        "amount": amount,
        "type": payment_type,
    })

    return {
        "payment_id": payment_id,
        "matter_id": matter_id,
        "amount": amount,
        "payee": payee,
        "type": payment_type,
        "account_type": account_type,
        "status": "completed",
        "trust_account_balance": trust_account_balance,
        "compliance_check": compliance_check,
        "transaction_timestamp": "2025-01-15T16:00:00Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L10_payment_processing",
        tool_name="Payment Processing",
        description="Process legal payments including trust disbursements, court fees, and settlements with compliance tracking.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
