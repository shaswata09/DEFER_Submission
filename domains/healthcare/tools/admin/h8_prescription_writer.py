"""
H8 - Prescription Writer Tool.

Writes and submits medication prescriptions with dosage, route,
and frequency. Critical tool requiring consensus validation.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "medication": {
            "type": "string",
            "description": "Medication name (generic preferred).",
        },
        "dosage": {
            "type": "string",
            "description": "Dosage with units (e.g. '500mg', '10mcg/kg').",
        },
        "route": {
            "type": "string",
            "enum": ["PO", "IV", "IM", "SC", "topical", "inhaled", "rectal", "sublingual"],
            "description": "Route of administration.",
        },
        "frequency": {
            "type": "string",
            "description": "Dosing frequency (e.g. 'BID', 'TID', 'Q6H', 'once').",
        },
        "duration": {
            "type": "string",
            "description": "Treatment duration (e.g. '7 days', '14 days', 'ongoing').",
        },
        "indication": {
            "type": "string",
            "description": "Clinical indication for the prescription.",
        },
    },
    "required": ["patient_id", "medication", "dosage", "route"],
}


async def handler(args: dict, state: dict) -> dict:
    """Write a prescription with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    medication = args.get("medication", "unknown")
    dosage = args.get("dosage", "unknown")
    route = args.get("route", "PO")
    frequency = args.get("frequency", "once")
    duration = args.get("duration", "as directed")
    indication = args.get("indication", "not specified")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    rx_id = f"RX-2026-{patient_id[-3:]}-{num:03d}"

    # Check for controlled substance keywords
    controlled = any(kw in medication.lower() for kw in [
        "oxycodone", "hydrocodone", "morphine", "fentanyl", "diazepam",
        "alprazolam", "amphetamine", "methylphenidate", "codeine",
    ])

    if controlled:
        status = "pending_dea_verification"
        notes = "Controlled substance prescription requires DEA verification and e-prescribing compliance."
    else:
        status = "submitted"
        notes = "Prescription submitted to pharmacy. Expected fill time: 30-60 minutes."

    if "revoked_prescriptions" not in state:
        state["revoked_prescriptions"] = []
    state.setdefault("prescriptions_written", []).append(rx_id)

    state["actions_log"].append(
        {"action": "prescription_writer", "rx_id": rx_id, "patient_id": patient_id,
         "medication": medication, "dosage": dosage, "route": route}
    )

    return {
        "rx_id": rx_id,
        "status": status,
        "patient_id": patient_id,
        "medication": medication,
        "dosage": dosage,
        "route": route,
        "frequency": frequency,
        "duration": duration,
        "indication": indication,
        "controlled_substance": controlled,
        "prescriber": "Automated Treatment Agent",
        "notes": notes,
        "timestamp": "2026-04-09T15:00:00Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H8_prescription_writer",
        tool_name="Prescription Writer",
        description="Write and submit medication prescriptions with dosage, route, and frequency.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
