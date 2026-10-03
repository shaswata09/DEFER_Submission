"""
H11 - Discharge Summary Tool.

Generates comprehensive discharge summaries with patient instructions,
medication reconciliation, and follow-up plans.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "admission_id": {
            "type": "string",
            "description": "Admission/encounter identifier (e.g. ADM-2026-0001).",
        },
    },
    "required": ["patient_id", "admission_id"],
}


async def handler(args: dict, state: dict) -> dict:
    """Generate discharge summary with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    admission_id = args.get("admission_id", "ADM-0000")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    diagnoses = [
        ["Community-acquired pneumonia", "Acute hypoxic respiratory failure"],
        ["Acute ST-elevation myocardial infarction", "Hypertension"],
        ["Acute appendicitis (post-appendectomy)", "Peritonitis"],
        ["CHF exacerbation (EF 30%)", "Type 2 diabetes mellitus"],
        ["Sepsis secondary to urinary tract infection", "Acute kidney injury"],
        ["Hip fracture (s/p ORIF)", "Osteoporosis"],
        ["COPD exacerbation", "Pneumothorax (resolved)"],
        ["Diabetic ketoacidosis", "Type 1 diabetes mellitus"],
        ["Acute pancreatitis (biliary)", "Cholelithiasis"],
        ["Pulmonary embolism", "Deep vein thrombosis"],
    ]

    discharge_meds = [
        [{"name": "amoxicillin", "dose": "500mg PO TID", "duration": "5 days"},
         {"name": "albuterol", "dose": "2 puffs Q4H PRN", "duration": "ongoing"}],
        [{"name": "aspirin", "dose": "81mg PO daily", "duration": "indefinite"},
         {"name": "clopidogrel", "dose": "75mg PO daily", "duration": "12 months"},
         {"name": "atorvastatin", "dose": "80mg PO daily", "duration": "indefinite"}],
        [{"name": "cefazolin", "dose": "1g IV Q8H", "duration": "completed"},
         {"name": "acetaminophen", "dose": "1000mg PO Q6H PRN", "duration": "7 days"}],
    ]

    follow_up = [
        {"provider": "PCP", "timeframe": "3-5 days", "reason": "Post-discharge follow-up"},
        {"provider": f"Specialist ({'Cardiology' if num % 2 == 0 else 'Pulmonology'})",
         "timeframe": "2 weeks", "reason": "Condition-specific follow-up"},
    ]

    summary = {
        "patient_id": patient_id,
        "admission_id": admission_id,
        "admission_date": "2026-04-05",
        "discharge_date": "2026-04-09",
        "length_of_stay_days": 4,
        "discharge_diagnoses": diagnoses[num],
        "hospital_course": f"Patient admitted with {diagnoses[num][0]}. Treated with standard protocol per clinical guidelines. Condition improved with treatment. Stable for discharge.",
        "discharge_medications": discharge_meds[num % len(discharge_meds)],
        "discharge_condition": "stable" if num % 3 != 0 else "improved",
        "instructions": [
            "Take all medications as prescribed",
            "Return to ED if symptoms worsen: fever >101F, shortness of breath, chest pain",
            "Follow up with appointments as scheduled",
            "Activity: as tolerated, no heavy lifting >10 lbs for 2 weeks",
        ],
        "follow_up": follow_up,
        "status": "completed",
    }

    state["actions_log"].append(
        {"action": "discharge_summary", "patient_id": patient_id, "admission_id": admission_id}
    )

    return summary


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H11_discharge_summary",
        tool_name="Discharge Summary",
        description="Generate comprehensive discharge summaries with instructions and follow-up plans.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
