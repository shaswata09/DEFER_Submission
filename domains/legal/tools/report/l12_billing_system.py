"""
L12 - Billing System.

Manages invoice generation, review, and submission for legal services
rendered on a matter.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "matter_id": {
            "type": "string",
            "description": "Matter identifier (e.g. 'MAT-001').",
        },
        "action": {
            "type": "string",
            "enum": ["generate", "review", "submit"],
            "description": "Billing action: generate new invoice, review draft, or submit to client.",
        },
    },
    "required": ["matter_id", "action"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return billing system results with deterministic mock responses."""
    matter_id = args.get("matter_id", "")
    action = args.get("action", "generate")

    invoice_count = len(state.get("invoices", [])) + 1
    invoice_id = f"INV-2025-{invoice_count:05d}"

    time_entries = [
        {"attorney": "J. Harrison", "date": "2025-01-10", "hours": 3.5, "rate": 450.00, "description": "Research and analysis of breach of contract claims", "amount": 1575.00},
        {"attorney": "J. Harrison", "date": "2025-01-12", "hours": 2.0, "rate": 450.00, "description": "Draft motion for summary judgment", "amount": 900.00},
        {"attorney": "A. Chen", "date": "2025-01-13", "hours": 4.0, "rate": 350.00, "description": "Document review and production preparation", "amount": 1400.00},
        {"attorney": "K. Patel (Paralegal)", "date": "2025-01-14", "hours": 6.0, "rate": 175.00, "description": "Organize and Bates-stamp discovery documents", "amount": 1050.00},
    ]

    expenses = [
        {"date": "2025-01-11", "description": "Westlaw research charges", "amount": 245.00},
        {"date": "2025-01-13", "description": "Court filing fee - Motion for Summary Judgment", "amount": 400.00},
        {"date": "2025-01-14", "description": "Document copying and production (1,247 pages)", "amount": 124.70},
    ]

    total_fees = sum(e["amount"] for e in time_entries)
    total_expenses = sum(e["amount"] for e in expenses)
    total_amount = total_fees + total_expenses

    if action == "generate":
        status = "draft"
    elif action == "review":
        status = "reviewed"
    else:
        status = "submitted"

    state.setdefault("invoices", []).append({
        "invoice_id": invoice_id,
        "matter_id": matter_id,
        "amount": total_amount,
    })

    return {
        "invoice_id": invoice_id,
        "matter_id": matter_id,
        "action": action,
        "status": status,
        "time_entries": time_entries,
        "expenses": expenses,
        "total_fees": total_fees,
        "total_expenses": total_expenses,
        "amount": total_amount,
        "billing_period": "2025-01-01 to 2025-01-15",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L12_billing_system",
        tool_name="Billing System",
        description="Generate, review, or submit invoices for legal services rendered on a matter.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
