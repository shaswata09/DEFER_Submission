"""
L7 - Contract Analyzer.

Analyzes contracts for clauses, risks, recommendations, and redline
suggestions based on specified analysis type.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "document_id": {
            "type": "string",
            "description": "Document identifier for the contract to analyze (e.g. 'DOC-001').",
        },
        "analysis_type": {
            "type": "string",
            "description": "Type of analysis: 'full_review', 'risk_assessment', 'clause_extraction', 'redline'.",
        },
    },
    "required": ["document_id", "analysis_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return contract analysis results with deterministic mock responses."""
    document_id = args.get("document_id", "")
    analysis_type = args.get("analysis_type", "full_review")

    clauses = [
        {"clause_id": "CL-01", "type": "indemnification", "section": "8.1", "risk_level": "high", "text_summary": "Broad indemnification clause requiring Client to indemnify Vendor against all claims including those arising from Vendor's own negligence."},
        {"clause_id": "CL-02", "type": "limitation_of_liability", "section": "8.3", "risk_level": "medium", "text_summary": "Liability capped at 12 months of fees paid. Excludes consequential, incidental, and punitive damages."},
        {"clause_id": "CL-03", "type": "termination", "section": "10.2", "risk_level": "low", "text_summary": "Either party may terminate with 30 days written notice. Vendor retains right to terminate immediately for non-payment."},
        {"clause_id": "CL-04", "type": "non_compete", "section": "12.1", "risk_level": "high", "text_summary": "24-month non-compete covering all jurisdictions where Vendor operates. Overly broad geographic and temporal scope."},
        {"clause_id": "CL-05", "type": "governing_law", "section": "14.1", "risk_level": "low", "text_summary": "Governed by laws of State of Delaware. Disputes subject to binding arbitration in Wilmington, DE."},
    ]

    risks = [
        {"risk_id": "RSK-01", "severity": "high", "description": "Indemnification clause (8.1) is one-sided and includes carve-out for Vendor negligence. Client bears disproportionate risk."},
        {"risk_id": "RSK-02", "severity": "high", "description": "Non-compete (12.1) is likely unenforceable due to overbroad geographic scope but creates litigation risk."},
        {"risk_id": "RSK-03", "severity": "medium", "description": "Liability cap excludes consequential damages which may include lost profits critical to Client's business."},
    ]

    recommendations = [
        "Negotiate mutual indemnification in Section 8.1 with carve-out for gross negligence and willful misconduct.",
        "Narrow non-compete in Section 12.1 to specific geographic markets and reduce duration to 12 months.",
        "Add consequential damages carve-out for data breach and IP infringement claims.",
        "Include a most-favored-nation clause for pricing adjustments.",
    ]

    redline_suggestions = [
        {"section": "8.1", "original": "Client shall indemnify and hold harmless Vendor...", "proposed": "Each Party shall indemnify the other Party...", "rationale": "Convert to mutual indemnification."},
        {"section": "12.1", "original": "...in any jurisdiction where Vendor operates...", "proposed": "...within the State of Delaware and contiguous states...", "rationale": "Narrow geographic scope to enforceable bounds."},
    ]

    state.setdefault("contracts_analyzed", []).append(document_id)

    return {
        "document_id": document_id,
        "analysis_type": analysis_type,
        "clauses": clauses,
        "risks": risks,
        "recommendations": recommendations,
        "redline_suggestions": redline_suggestions,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L7_contract_analyzer",
        tool_name="Contract Analyzer",
        description="Analyze contracts for clauses, risks, recommendations, and redline suggestions.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
