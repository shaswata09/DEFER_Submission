"""
H3 - Lab Results Tool.

Retrieves laboratory test results with reference ranges and abnormal flags.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patient_id": {
            "type": "string",
            "description": "Patient identifier (e.g. PAT-001).",
        },
        "test_type": {
            "type": "string",
            "enum": ["CBC", "BMP", "LFT", "coagulation", "cardiac_enzymes", "urinalysis", "all"],
            "description": "Type of laboratory test to retrieve.",
        },
    },
    "required": ["patient_id", "test_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return lab results with deterministic mock responses."""
    patient_id = args.get("patient_id", "PAT-000")
    test_type = args.get("test_type", "all")

    num = int("".join(c for c in patient_id if c.isdigit()) or "0") % 10

    has_abnormal = num % 3 != 0

    cbc = {
        "WBC": {"value": 12.8 if has_abnormal else 7.2, "unit": "K/uL", "range": "4.5-11.0", "flag": "HIGH" if has_abnormal else "NORMAL"},
        "hemoglobin": {"value": 10.2 if has_abnormal else 14.1, "unit": "g/dL", "range": "12.0-16.0", "flag": "LOW" if has_abnormal else "NORMAL"},
        "platelets": {"value": 145 + num * 20, "unit": "K/uL", "range": "150-400", "flag": "NORMAL"},
        "hematocrit": {"value": 31.5 if has_abnormal else 42.3, "unit": "%", "range": "36-46", "flag": "LOW" if has_abnormal else "NORMAL"},
    }

    bmp = {
        "glucose": {"value": 210 if has_abnormal else 95, "unit": "mg/dL", "range": "70-100", "flag": "HIGH" if has_abnormal else "NORMAL"},
        "BUN": {"value": 32 if has_abnormal else 15, "unit": "mg/dL", "range": "7-20", "flag": "HIGH" if has_abnormal else "NORMAL"},
        "creatinine": {"value": 1.8 if has_abnormal else 0.9, "unit": "mg/dL", "range": "0.6-1.2", "flag": "HIGH" if has_abnormal else "NORMAL"},
        "sodium": {"value": 138 + num % 5, "unit": "mEq/L", "range": "136-145", "flag": "NORMAL"},
        "potassium": {"value": 5.6 if has_abnormal else 4.2, "unit": "mEq/L", "range": "3.5-5.0", "flag": "HIGH" if has_abnormal else "NORMAL"},
    }

    cardiac = {
        "troponin_I": {"value": 0.85 if has_abnormal else 0.01, "unit": "ng/mL", "range": "<0.04", "flag": "CRITICAL" if has_abnormal else "NORMAL"},
        "BNP": {"value": 850 if has_abnormal else 45, "unit": "pg/mL", "range": "<100", "flag": "HIGH" if has_abnormal else "NORMAL"},
        "CK_MB": {"value": 28 if has_abnormal else 3, "unit": "ng/mL", "range": "0-5", "flag": "HIGH" if has_abnormal else "NORMAL"},
    }

    results = {"patient_id": patient_id, "test_type": test_type, "collection_time": "2026-04-09T12:00:00Z"}

    if test_type == "CBC":
        results["results"] = cbc
    elif test_type == "BMP":
        results["results"] = bmp
    elif test_type == "cardiac_enzymes":
        results["results"] = cardiac
    elif test_type == "all":
        results["results"] = {"CBC": cbc, "BMP": bmp, "cardiac_enzymes": cardiac}
    else:
        results["results"] = {"status": "pending", "estimated_completion": "2026-04-09T16:00:00Z"}

    results["critical_flags"] = [k for section in [cbc, bmp, cardiac] for k, v in section.items() if v.get("flag") == "CRITICAL"] if has_abnormal else []

    state["actions_log"].append(
        {"action": "lab_results", "patient_id": patient_id, "test_type": test_type}
    )

    return results


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H3_lab_results",
        tool_name="Lab Results",
        description="Retrieve laboratory test results with reference ranges and abnormal flags.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
