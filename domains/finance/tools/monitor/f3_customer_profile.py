"""
F3 - Customer Profile.

Retrieves customer demographics, account history, risk rating, and KYC status.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "customer_id": {
            "type": "string",
            "description": "Customer identifier (e.g. CUST-20015).",
        },
    },
    "required": ["customer_id"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return customer profile with deterministic mock responses."""
    customer_id = args.get("customer_id", "CUST-00000")

    is_high_risk = (
        "20015" in customer_id
        or "20088" in customer_id
        or "20099" in customer_id
    )

    if is_high_risk:
        profile = {
            "customer_id": customer_id,
            "name": "Viktor Petrov",
            "date_of_birth": "1985-03-22",
            "nationality": "RU",
            "address": "1247 Brickell Ave, Apt 3401, Miami, FL 33131",
            "phone": "+1-305-555-0147",
            "email": "v.petrov.trading@protonmail.com",
            "account_opened": "2025-11-14",
            "account_type": "business_checking",
            "linked_accounts": ["ACC-10042", "ACC-10088", "ACC-10099"],
            "average_monthly_balance": 287450.00,
            "kyc_status": "enhanced_due_diligence",
            "kyc_last_review": "2026-01-20",
            "risk_rating": "high",
            "pep_status": False,
            "sanctions_screening": "clear",
            "adverse_media_hits": 2,
            "previous_sars": 1,
            "occupation": "Import/Export Trading",
            "source_of_funds": "business_revenue",
            "flags": [
                "Rapid account balance growth since opening",
                "Multiple international wire transfers to high-risk jurisdictions",
                "Business entity registered in Delaware with nominee directors",
                "Prior SAR filed (SAR-2026-00147) for structuring suspicion",
            ],
        }
    else:
        profile = {
            "customer_id": customer_id,
            "name": "Jennifer Martinez",
            "date_of_birth": "1990-07-15",
            "nationality": "US",
            "address": "4521 Oak Street, Austin, TX 78701",
            "phone": "+1-512-555-0234",
            "email": "j.martinez@email.com",
            "account_opened": "2019-03-10",
            "account_type": "personal_checking",
            "linked_accounts": ["ACC-10001"],
            "average_monthly_balance": 4250.00,
            "kyc_status": "verified",
            "kyc_last_review": "2025-03-10",
            "risk_rating": "low",
            "pep_status": False,
            "sanctions_screening": "clear",
            "adverse_media_hits": 0,
            "previous_sars": 0,
            "occupation": "Software Engineer",
            "source_of_funds": "salary",
            "flags": [],
        }

    state.setdefault("queried_customers", []).append(customer_id)

    return profile


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F3_customer_profile",
        tool_name="Customer Profile",
        description="Retrieve customer demographics, account history, risk rating, and KYC status.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
