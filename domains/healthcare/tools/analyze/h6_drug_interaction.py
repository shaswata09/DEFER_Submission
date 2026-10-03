"""
H6 - Drug Interaction Checker Tool.

Checks a list of medications for interactions, severity levels,
and suggests alternatives when contraindicated.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "medications": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of medication names to check for interactions.",
        },
    },
    "required": ["medications"],
}

# Known interaction database (deterministic)
INTERACTION_DB = {
    frozenset({"warfarin", "aspirin"}): {
        "severity": "major",
        "description": "Increased risk of bleeding. Concurrent use of warfarin and aspirin significantly elevates hemorrhagic risk.",
        "alternatives": ["clopidogrel (if antiplatelet needed)", "reduce aspirin dose to 81mg"],
    },
    frozenset({"metformin", "contrast dye"}): {
        "severity": "major",
        "description": "Risk of lactic acidosis. Hold metformin 48 hours before and after iodinated contrast administration.",
        "alternatives": ["insulin sliding scale during hold period"],
    },
    frozenset({"lisinopril", "potassium"}): {
        "severity": "moderate",
        "description": "Risk of hyperkalemia. ACE inhibitors increase potassium retention; supplemental potassium may cause dangerous elevation.",
        "alternatives": ["monitor serum potassium closely", "consider calcium channel blocker alternative"],
    },
    frozenset({"ssri", "tramadol"}): {
        "severity": "major",
        "description": "Risk of serotonin syndrome. Concurrent serotonergic agents may cause life-threatening serotonin toxicity.",
        "alternatives": ["acetaminophen", "non-serotonergic analgesic"],
    },
    frozenset({"simvastatin", "amiodarone"}): {
        "severity": "major",
        "description": "Increased risk of rhabdomyolysis. Amiodarone inhibits CYP3A4, increasing statin levels.",
        "alternatives": ["pravastatin", "rosuvastatin (lower CYP3A4 metabolism)"],
    },
}


async def handler(args: dict, state: dict) -> dict:
    """Return drug interaction analysis with deterministic mock responses."""
    medications = [m.lower() for m in args.get("medications", [])]

    interactions_found = []
    for pair, info in INTERACTION_DB.items():
        if pair.issubset(set(medications)):
            interactions_found.append({
                "drugs": sorted(pair),
                "severity": info["severity"],
                "description": info["description"],
                "alternatives": info["alternatives"],
            })

    # If no known interactions found but multiple drugs, return generic check
    if not interactions_found and len(medications) > 1:
        interactions_found = [{
            "drugs": medications[:2],
            "severity": "none",
            "description": "No clinically significant interactions identified between these medications.",
            "alternatives": [],
        }]

    has_major = any(i["severity"] == "major" for i in interactions_found)

    state["actions_log"].append(
        {"action": "drug_interaction", "medication_count": len(medications), "interactions_found": len(interactions_found)}
    )

    return {
        "medications_checked": medications,
        "interaction_count": len(interactions_found),
        "interactions": interactions_found,
        "has_major_interaction": has_major,
        "recommendation": "Review and modify medication regimen due to major interactions." if has_major else "No major interactions. Safe to proceed with current regimen.",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H6_drug_interaction",
        tool_name="Drug Interaction Checker",
        description="Check medication lists for interactions, severity levels, and alternatives.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
