"""
L9 - Document Signing.

Initiates and manages document signing workflows with specified signers
and methods. Returns signing status and audit trail.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "document_id": {
            "type": "string",
            "description": "Document identifier to be signed (e.g. 'DOC-001').",
        },
        "signers": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of signer names or identifiers.",
        },
        "method": {
            "type": "string",
            "description": "Signing method: 'e_signature', 'wet_ink', 'notarized'.",
        },
    },
    "required": ["document_id", "signers", "method"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return document signing results with deterministic mock responses."""
    document_id = args.get("document_id", "")
    signers = args.get("signers", [])
    method = args.get("method", "e_signature")

    signing_count = len(state.get("signing_workflows", [])) + 1
    signing_id = f"SGN-2025-{signing_count:05d}"

    signer_statuses = []
    for i, signer in enumerate(signers):
        signer_statuses.append({
            "signer": signer,
            "status": "completed" if i == 0 else "pending",
            "signed_at": "2025-01-15T15:10:00Z" if i == 0 else None,
            "ip_address": "198.51.100.42" if i == 0 else None,
        })

    overall_status = "completed" if len(signers) == 1 else "partially_executed"

    audit_trail = [
        {"event": "signing_initiated", "timestamp": "2025-01-15T14:55:00Z", "actor": "system", "details": f"Signing workflow created for {document_id}"},
        {"event": "document_viewed", "timestamp": "2025-01-15T15:05:00Z", "actor": signers[0] if signers else "unknown", "details": "Document opened and reviewed"},
        {"event": "signature_applied", "timestamp": "2025-01-15T15:10:00Z", "actor": signers[0] if signers else "unknown", "details": f"Signature applied via {method}"},
    ]

    state.setdefault("signing_workflows", []).append({
        "signing_id": signing_id,
        "document_id": document_id,
    })

    return {
        "signing_id": signing_id,
        "document_id": document_id,
        "method": method,
        "status": overall_status,
        "signer_statuses": signer_statuses,
        "audit_trail": audit_trail,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L9_document_signing",
        tool_name="Document Signing",
        description="Initiate document signing workflows with specified signers and method, returning status and audit trail.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
