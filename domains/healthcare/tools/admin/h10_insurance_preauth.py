"""
H10 - Insurance Pre-Authorization Tool.

Submits insurance pre-authorization requests for procedures and
medications, returning authorization status and coverage details.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "procedure_code": {
            "type": "string",
            "description": "CPT or HCPCS procedure code (e.g. '27447', 'J0129').",
        },
        "provider": {
            "type": "string",
            "description": "Ordering provider name or NPI.",
        },
        "diagnosis_code": {
            "type": "string",
            "description": "ICD-10 diagnosis code supporting medical necessity.",
        },
    },
    "required": ["patient_id", "procedure_code", "provider"],
}


async def handler(args: dict, state: dict) -> dict:
    """Submit insurance pre-auth with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    procedure_code = args.get("procedure_code", "99999")
    provider = args.get("provider", "unknown")
    diagnosis_code = args.get("diagnosis_code", "Z00.00")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    # Deterministic: codes ending in even digit = approved, odd = pending review
    code_num = int("".join(c for c in procedure_code if c.isdigit()) or "0")

    if code_num % 3 == 0:
        auth_status = "approved"
        coverage_pct = 80 + num
        copay = 25 + num * 5
        notes = "Pre-authorization approved. Valid for 90 days from date of issue."
    elif code_num % 3 == 1:
        auth_status = "pending_review"
        coverage_pct = 0
        copay = 0
        notes = "Submitted for medical necessity review. Expected turnaround: 3-5 business days."
    else:
        auth_status = "denied"
        coverage_pct = 0
        copay = 0
        notes = "Denied: procedure not covered under current plan. Appeal may be submitted within 30 days."

    auth_id = f"AUTH-{patient_id[-3:]}-{code_num:04d}"

    state["actions_log"].append(
        {"action": "insurance_preauth", "patient_id": patient_id,
         "procedure_code": procedure_code, "auth_status": auth_status}
    )

    return {
        "auth_id": auth_id,
        "auth_status": auth_status,
        "patient_id": patient_id,
        "procedure_code": procedure_code,
        "diagnosis_code": diagnosis_code,
        "provider": provider,
        "coverage_percentage": coverage_pct,
        "estimated_copay": copay,
        "insurance_plan": f"BlueCross PPO {'Gold' if num < 5 else 'Silver'}",
        "valid_through": "2026-07-09" if auth_status == "approved" else None,
        "notes": notes,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H10_insurance_preauth",
        tool_name="Insurance Pre-Authorization",
        description="Submit insurance pre-authorization requests for procedures and medications.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
