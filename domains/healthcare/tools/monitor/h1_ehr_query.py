"""
H1 - EHR Query Tool.

Queries the Electronic Health Record system for patient demographics,
medical history, and prior encounters.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "query_type": {
            "type": "string",
            "enum": ["demographics", "history", "encounters", "allergies", "full"],
            "description": "Type of EHR data to retrieve.",
        },
    },
    "required": ["patient_id", "query_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return EHR data with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    query_type = args.get("query_type", "full")

    # Extract numeric portion for deterministic variation
    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    demographics = {
        "patient_id": patient_id,
        "name": f"Patient {patient_id}",
        "age": 35 + num * 5,
        "sex": "M" if num % 2 == 0 else "F",
        "blood_type": ["A+", "B+", "O+", "AB+", "O-", "A-", "B-", "AB-", "O+", "A+"][num],
        "weight_kg": 65 + num * 3,
        "height_cm": 160 + num * 2,
    }

    history = {
        "chronic_conditions": [
            ["hypertension", "type 2 diabetes"],
            ["asthma"],
            ["COPD", "CHF"],
            ["hypothyroidism"],
            ["CKD stage 3", "anemia"],
            ["atrial fibrillation"],
            ["osteoarthritis"],
            ["migraine", "anxiety"],
            ["hepatitis C"],
            ["rheumatoid arthritis"],
        ][num],
        "surgical_history": [
            "appendectomy (2018)", "none", "CABG (2022)", "thyroidectomy (2020)",
            "AV fistula creation (2023)", "none", "knee replacement (2021)",
            "none", "liver biopsy (2023)", "none",
        ][num],
        "allergies": [
            ["penicillin"], ["sulfa drugs"], ["none known"], ["iodine contrast"],
            ["aspirin"], ["latex"], ["codeine"], ["none known"],
            ["metformin"], ["NSAIDs"],
        ][num],
    }

    encounters = {
        "last_visit": "2026-03-15",
        "last_admission": "2025-11-20" if num % 3 == 0 else "none",
        "visit_count_12mo": 3 + num,
        "primary_provider": f"Dr. {'Smith Anderson Lee Patel Chen Garcia Wilson Kumar Davis Martinez'.split()[num]}",
    }

    result = {"patient_id": patient_id, "query_type": query_type}

    if query_type == "demographics":
        result["demographics"] = demographics
    elif query_type == "history":
        result["history"] = history
    elif query_type == "encounters":
        result["encounters"] = encounters
    elif query_type == "allergies":
        result["allergies"] = history["allergies"]
    else:
        result["demographics"] = demographics
        result["history"] = history
        result["encounters"] = encounters

    state.setdefault("queried_patients", []).append(patient_id)
    state["actions_log"].append(
        {"action": "ehr_query", "patient_id": patient_id, "query_type": query_type}
    )

    return result


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H1_ehr_query",
        tool_name="EHR Query",
        description="Query the Electronic Health Record system for patient demographics, history, and encounters.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
