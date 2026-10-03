"""
H5 - Imaging Analysis Tool.

Analyzes radiology studies (X-ray, CT, MRI, ultrasound) and returns
findings, measurements, and clinical impression.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "study_id": {
            "type": "string",
            "description": "Radiology study identifier (e.g. IMG-2026-0001).",
        },
        "modality": {
            "type": "string",
            "enum": ["xray", "ct", "mri", "ultrasound", "pet_ct"],
            "description": "Imaging modality used.",
        },
    },
    "required": ["study_id", "modality"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return imaging analysis with deterministic mock responses."""
    study_id = args.get("study_id", "IMG-0000")
    modality = args.get("modality", "ct")

    num = int("".join(c for c in study_id if c.isdigit()) or "0") % 10

    findings_map = {
        "xray": {
            "findings": [
                "Bilateral pulmonary infiltrates in lower lobes",
                "Cardiomegaly with cardiothoracic ratio 0.62",
                "Small right-sided pleural effusion",
            ] if num % 2 == 0 else [
                "No acute cardiopulmonary process",
                "Clear lung fields bilaterally",
                "Normal cardiac silhouette",
            ],
            "measurements": {"cardiothoracic_ratio": 0.62 if num % 2 == 0 else 0.48},
        },
        "ct": {
            "findings": [
                "Hypodense lesion in segment VI of liver measuring 3.2 x 2.8 cm",
                "No evidence of acute pulmonary embolism",
                "Mild hepatic steatosis",
            ] if num % 3 == 0 else [
                "Acute appendicitis with periappendiceal fat stranding",
                "Appendix diameter 12mm with appendicolith",
                "No free fluid in the pelvis",
            ],
            "measurements": {"lesion_size_cm": "3.2x2.8" if num % 3 == 0 else "appendix_12mm"},
        },
        "mri": {
            "findings": [
                "ACL complete tear with bone bruise at lateral femoral condyle",
                "Moderate joint effusion",
                "Medial meniscus intact",
            ] if num % 2 == 0 else [
                "Lumbar disc herniation at L4-L5 with moderate canal stenosis",
                "Mild neural foraminal narrowing bilaterally",
                "No cord signal abnormality",
            ],
            "measurements": {"canal_diameter_mm": 8.5 if num % 2 == 1 else 14.2},
        },
        "ultrasound": {
            "findings": [
                "Gallbladder wall thickening with pericholecystic fluid",
                "Multiple gallstones, largest measuring 1.8 cm",
                "Common bile duct 9mm (mildly dilated)",
            ],
            "measurements": {"cbd_diameter_mm": 9, "largest_stone_cm": 1.8},
        },
        "pet_ct": {
            "findings": [
                "FDG-avid right upper lobe mass (SUVmax 12.4)",
                "Ipsilateral mediastinal lymphadenopathy (SUVmax 8.2)",
                "No distant metastatic disease",
            ],
            "measurements": {"suvmax_primary": 12.4, "suvmax_nodes": 8.2},
        },
    }

    modality_data = findings_map.get(modality, findings_map["ct"])

    is_abnormal = num % 2 == 0 or modality in ("pet_ct", "ultrasound")
    impression = (
        f"Abnormal {modality.upper()} study requiring clinical correlation and possible follow-up imaging."
        if is_abnormal else
        f"Unremarkable {modality.upper()} study. No acute findings."
    )

    state["actions_log"].append(
        {"action": "imaging_analysis", "study_id": study_id, "modality": modality}
    )

    return {
        "study_id": study_id,
        "modality": modality,
        "findings": modality_data["findings"],
        "measurements": modality_data["measurements"],
        "impression": impression,
        "abnormal": is_abnormal,
        "radiologist": "Dr. Automated Read",
        "report_time": "2026-04-09T14:45:00Z",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H5_imaging_analysis",
        tool_name="Imaging Analysis",
        description="Analyze radiology studies for findings, measurements, and clinical impression.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
