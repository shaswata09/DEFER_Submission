"""
H9 - Procedure Scheduler Tool.

Schedules clinical procedures with urgency level, room assignment,
and team allocation.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "procedure": {
            "type": "string",
            "description": "Name of the procedure to schedule.",
        },
        "urgency": {
            "type": "string",
            "enum": ["emergent", "urgent", "elective"],
            "description": "Urgency level of the procedure.",
        },
    },
    "required": ["patient_id", "procedure", "urgency"],
}


async def handler(args: dict, state: dict) -> dict:
    """Schedule a procedure with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    procedure = args.get("procedure", "unknown")
    urgency = args.get("urgency", "elective")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    rooms = ["OR-1", "OR-2", "Cath Lab", "IR Suite", "Endo Suite",
             "OR-3", "OR-4", "Minor Procedure Room A", "Cath Lab 2", "OR-5"]
    teams = [
        ["Dr. Smith (Surgeon)", "Dr. Lee (Anesthesia)", "RN Johnson"],
        ["Dr. Patel (Cardiology)", "Dr. Chen (Anesthesia)", "RN Williams"],
        ["Dr. Garcia (Radiology)", "Dr. Kumar (Anesthesia)", "RN Davis"],
        ["Dr. Anderson (GI)", "CRNA Martinez", "RN Taylor"],
        ["Dr. Wilson (Orthopedics)", "Dr. Lee (Anesthesia)", "RN Brown"],
    ]

    if urgency == "emergent":
        slot = "2026-04-09T16:00:00Z"
        wait_time = "30 minutes"
    elif urgency == "urgent":
        slot = "2026-04-10T08:00:00Z"
        wait_time = "12-18 hours"
    else:
        slot = "2026-04-14T10:00:00Z"
        wait_time = "5 days"

    room = rooms[num]
    team = teams[num % len(teams)]

    state["actions_log"].append(
        {"action": "procedure_scheduler", "patient_id": patient_id,
         "procedure": procedure, "urgency": urgency}
    )

    return {
        "schedule_id": f"SCHED-{patient_id[-3:]}-{num:03d}",
        "patient_id": patient_id,
        "procedure": procedure,
        "urgency": urgency,
        "slot": slot,
        "room": room,
        "team": team,
        "estimated_duration": "60-90 minutes",
        "wait_time": wait_time,
        "pre_op_requirements": [
            "NPO after midnight",
            "CBC, BMP, coagulation panel",
            "Type and screen",
            "Consent form signed",
        ],
        "status": "confirmed",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H9_procedure_scheduler",
        tool_name="Procedure Scheduler",
        description="Schedule clinical procedures with urgency level, room, and team assignment.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
