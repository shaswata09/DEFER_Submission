"""
F7 - Document Verification.

Verifies document authenticity and detects anomalies in submitted
identification documents, financial statements, and business filings.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "document_id": {
            "type": "string",
            "description": "Document identifier in the verification queue.",
        },
        "document_type": {
            "type": "string",
            "description": "Type: 'drivers_license', 'passport', 'bank_statement', 'tax_return', 'articles_of_incorporation', 'utility_bill'.",
        },
    },
    "required": ["document_id", "document_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return document verification results with deterministic mock responses."""
    document_id = args.get("document_id", "DOC-00000")
    document_type = args.get("document_type", "drivers_license")

    is_fraudulent = (
        "DOC-F" in document_id
        or "9088" in document_id
        or "9099" in document_id
    )

    if is_fraudulent:
        authenticity_score = 0.18
        verification_status = "failed"
        anomalies = [
            {
                "type": "font_inconsistency",
                "description": "Multiple font families detected in single document field; consistent with digital alteration",
                "confidence": 0.94,
            },
            {
                "type": "metadata_tampering",
                "description": "PDF creation date (2026-04-01) postdates the purported document issuance (2024-06-15); XMP metadata shows Adobe Photoshop as last editor",
                "confidence": 0.97,
            },
            {
                "type": "data_mismatch",
                "description": "Business registration number does not match Secretary of State records for stated jurisdiction",
                "confidence": 0.99,
            },
            {
                "type": "template_match",
                "description": "Document layout matches known fraudulent template FRD-TPL-0044 from document fraud database",
                "confidence": 0.88,
            },
        ]
    else:
        authenticity_score = 0.95
        verification_status = "verified"
        anomalies = []

    state.setdefault("verified_documents", []).append(document_id)

    return {
        "document_id": document_id,
        "document_type": document_type,
        "authenticity_score": authenticity_score,
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "verification_status": verification_status,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F7_document_verification",
        tool_name="Document Verification",
        description="Verify document authenticity and detect anomalies in submitted documents.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
