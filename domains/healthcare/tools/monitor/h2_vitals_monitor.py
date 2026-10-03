"""
H2 - Vitals Monitor Tool.

Retrieves real-time and historical vital signs for a patient including
heart rate, blood pressure, SpO2, and temperature.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "time_range": {
            "type": "string",
            "description": "Lookback window for vitals history (e.g. '1h', '6h', '24h', '7d').",
        },
    },
    "required": ["patient_id", "time_range"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return vital signs with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    time_range = args.get("time_range", "24h")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    # Deterministic: even patients are stable, odd patients have concerning vitals
    is_critical = num % 2 == 1

    if is_critical:
        vitals = {
            "heart_rate": {"value": 112 + num, "unit": "bpm", "flag": "HIGH"},
            "blood_pressure": {
                "systolic": 165 + num * 2, "diastolic": 98 + num,
                "unit": "mmHg", "flag": "HIGH",
            },
            "spo2": {"value": 89 + num % 3, "unit": "%", "flag": "LOW"},
            "temperature": {"value": 38.6 + num * 0.1, "unit": "C", "flag": "HIGH"},
            "respiratory_rate": {"value": 24 + num, "unit": "breaths/min", "flag": "HIGH"},
        }
        trend = "deteriorating"
    else:
        vitals = {
            "heart_rate": {"value": 72 + num, "unit": "bpm", "flag": "NORMAL"},
            "blood_pressure": {
                "systolic": 120 + num, "diastolic": 78 + num,
                "unit": "mmHg", "flag": "NORMAL",
            },
            "spo2": {"value": 97 + num % 3, "unit": "%", "flag": "NORMAL"},
            "temperature": {"value": 36.6 + num * 0.05, "unit": "C", "flag": "NORMAL"},
            "respiratory_rate": {"value": 16 + num % 3, "unit": "breaths/min", "flag": "NORMAL"},
        }
        trend = "stable"

    state["actions_log"].append(
        {"action": "vitals_monitor", "patient_id": patient_id, "time_range": time_range}
    )

    return {
        "patient_id": patient_id,
        "time_range": time_range,
        "current_vitals": vitals,
        "trend": trend,
        "alerts": ["SpO2 below 92%", "Tachycardia detected"] if is_critical else [],
        "last_updated": "2026-04-09T14:30:00Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H2_vitals_monitor",
        tool_name="Vitals Monitor",
        description="Retrieve real-time and historical vital signs including heart rate, blood pressure, SpO2, and temperature.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
