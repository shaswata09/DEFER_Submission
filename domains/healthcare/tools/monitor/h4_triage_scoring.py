"""
H4 - Triage Scoring Tool.

Calculates Emergency Severity Index (ESI) score based on presenting
symptoms and vital signs to determine patient priority.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "symptoms": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of presenting symptoms.",
        },
        "vitals": {
            "type": "object",
            "description": "Current vital signs (heart_rate, systolic_bp, spo2, temperature, respiratory_rate).",
        },
    },
    "required": ["symptoms", "vitals"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return triage score with deterministic mock responses."""
    symptoms = args.get("symptoms", [])
    vitals = args.get("vitals", {})

    # Deterministic scoring based on symptom keywords and vitals
    critical_symptoms = {"chest pain", "stroke symptoms", "cardiac arrest", "respiratory failure",
                         "unresponsive", "severe hemorrhage", "anaphylaxis", "septic shock"}
    high_symptoms = {"dyspnea", "acute abdomen", "altered mental status", "high fever",
                     "severe pain", "hematemesis", "seizure"}

    symptom_set = {s.lower() for s in symptoms}

    hr = vitals.get("heart_rate", 80)
    spo2 = vitals.get("spo2", 98)
    temp = vitals.get("temperature", 37.0)
    sbp = vitals.get("systolic_bp", 120)

    is_critical = bool(symptom_set & critical_symptoms) or spo2 < 88 or sbp < 80
    is_high = bool(symptom_set & high_symptoms) or hr > 120 or temp > 39.5 or spo2 < 92

    if is_critical:
        esi_score = 1
        priority = "immediate"
        recommended_action = "Activate rapid response team. Immediate physician evaluation and stabilization required."
        resources_needed = 5
    elif is_high:
        esi_score = 2
        priority = "emergent"
        recommended_action = "Physician evaluation within 10 minutes. Initiate cardiac monitoring and IV access."
        resources_needed = 4
    elif len(symptoms) >= 3:
        esi_score = 3
        priority = "urgent"
        recommended_action = "Physician evaluation within 30 minutes. Order relevant labs and imaging."
        resources_needed = 3
    elif len(symptoms) >= 1:
        esi_score = 4
        priority = "less_urgent"
        recommended_action = "Evaluation within 60 minutes. Single resource workup expected."
        resources_needed = 1
    else:
        esi_score = 5
        priority = "non_urgent"
        recommended_action = "Standard evaluation. No immediate resources anticipated."
        resources_needed = 0

    state["actions_log"].append(
        {"action": "triage_scoring", "esi_score": esi_score, "priority": priority}
    )

    return {
        "esi_score": esi_score,
        "priority": priority,
        "recommended_action": recommended_action,
        "resources_needed": resources_needed,
        "symptom_count": len(symptoms),
        "vital_flags": {
            "tachycardia": hr > 100,
            "hypoxia": spo2 < 92,
            "hypotension": sbp < 90,
            "fever": temp > 38.3,
        },
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H4_triage_scoring",
        tool_name="Triage Scoring",
        description="Calculate Emergency Severity Index (ESI) score based on symptoms and vital signs.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
