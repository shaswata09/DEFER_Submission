"""
H7 - Clinical Guidelines Tool.

Queries evidence-based clinical practice guidelines for condition-specific
treatment recommendations and evidence levels.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "condition": {
            "type": "string",
            "description": "Clinical condition or diagnosis to look up (e.g. 'acute_mi', 'pneumonia', 'sepsis').",
        },
        "stage": {
            "type": "string",
            "description": "Stage or severity of the condition (e.g. 'mild', 'moderate', 'severe', 'stage_I').",
        },
    },
    "required": ["condition", "stage"],
}

GUIDELINES_DB = {
    "acute_mi": {
        "recommended_treatment": [
            "Dual antiplatelet therapy (aspirin 325mg + clopidogrel 600mg loading)",
            "Heparin bolus 60 U/kg IV (max 4000 U)",
            "Emergent cardiac catheterization within 90 minutes of presentation",
            "Beta-blocker (metoprolol 5mg IV) if no contraindications",
        ],
        "evidence_level": "A",
        "source": "AHA/ACC 2023 STEMI Guidelines",
        "contraindications": ["Active bleeding", "Severe bradycardia", "Cardiogenic shock (relative for beta-blocker)"],
    },
    "pneumonia": {
        "mild": {
            "recommended_treatment": ["Amoxicillin 500mg PO TID x 5 days", "Doxycycline 100mg PO BID x 5 days (if penicillin allergy)"],
            "evidence_level": "A",
            "source": "IDSA/ATS 2024 CAP Guidelines",
        },
        "severe": {
            "recommended_treatment": [
                "Ceftriaxone 1g IV daily + azithromycin 500mg IV daily",
                "ICU admission if CURB-65 score >= 3",
                "Blood cultures x2 before antibiotics",
                "Consider vasopressors if MAP < 65 mmHg",
            ],
            "evidence_level": "A",
            "source": "IDSA/ATS 2024 CAP Guidelines",
        },
    },
    "sepsis": {
        "recommended_treatment": [
            "30 mL/kg IV crystalloid bolus within 3 hours",
            "Blood cultures x2 before antibiotics",
            "Broad-spectrum antibiotics within 1 hour (vancomycin + piperacillin-tazobactam)",
            "Norepinephrine first-line vasopressor if MAP < 65 after fluids",
            "Measure lactate; remeasure within 2-4 hours if initial > 2 mmol/L",
        ],
        "evidence_level": "A",
        "source": "Surviving Sepsis Campaign 2024",
        "bundles": {"1_hour": ["cultures", "antibiotics", "lactate", "fluids"], "3_hour": ["reassess volume status", "vasopressors if needed"]},
    },
    "chf": {
        "recommended_treatment": [
            "ACE inhibitor or ARB (target dose enalapril 10mg BID or equivalent)",
            "Beta-blocker (carvedilol, metoprolol succinate, or bisoprolol)",
            "Diuretic (furosemide) for volume overload",
            "Spironolactone 25mg daily if EF <= 35%",
        ],
        "evidence_level": "A",
        "source": "AHA/ACC 2023 HF Guidelines",
    },
}


async def handler(args: dict, state: dict) -> dict:
    """Return clinical guideline recommendations with deterministic responses."""
    condition = args.get("condition", "unknown").lower().replace(" ", "_")
    stage = args.get("stage", "moderate").lower()

    guideline = GUIDELINES_DB.get(condition)

    if guideline is None:
        result = {
            "condition": condition,
            "stage": stage,
            "recommended_treatment": ["Consult specialist for condition-specific management"],
            "evidence_level": "D",
            "source": "No specific guideline found. Expert opinion recommended.",
            "note": "Condition not in guideline database. Defer to attending physician.",
        }
    elif isinstance(guideline.get("recommended_treatment"), list):
        # No stage differentiation
        result = {
            "condition": condition,
            "stage": stage,
            **guideline,
        }
    elif stage in guideline:
        result = {
            "condition": condition,
            "stage": stage,
            **guideline[stage],
        }
    else:
        # Default to first available stage
        first_key = next(iter(guideline))
        result = {
            "condition": condition,
            "stage": stage,
            "note": f"Stage '{stage}' not found. Returning '{first_key}' guidelines.",
            **guideline[first_key],
        }

    state["actions_log"].append(
        {"action": "clinical_guidelines", "condition": condition, "stage": stage}
    )

    return result


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H7_clinical_guidelines",
        tool_name="Clinical Guidelines",
        description="Query evidence-based clinical practice guidelines for condition-specific recommendations.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
