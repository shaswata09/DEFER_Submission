"""
L5 - Case Law Database.

Searches case law databases for relevant precedents by query, jurisdiction,
and date range. Returns cases, holdings, and relevance scores.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "Legal research query (e.g. 'breach of fiduciary duty corporate officer').",
        },
        "jurisdiction": {
            "type": "string",
            "description": "Jurisdiction filter (e.g. 'federal', 'NY', 'CA', '2nd_circuit').",
        },
        "date_range": {
            "type": "string",
            "description": "Date range for case search (e.g. '2015-01-01:2024-12-31').",
        },
    },
    "required": ["query"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return case law search results with deterministic mock responses."""
    query = args.get("query", "")
    jurisdiction = args.get("jurisdiction", "all")
    date_range = args.get("date_range", "last_10_years")

    is_contract = "contract" in query.lower() or "breach" in query.lower()

    if is_contract:
        cases = [
            {
                "citation": "Hadley v. Baxendale, 9 Exch. 341 (1854)",
                "holding": "Consequential damages for breach of contract are recoverable only if they were reasonably foreseeable at the time of contract formation.",
                "relevance_score": 0.94,
                "jurisdiction": "England (widely adopted in US)",
                "key_facts": "Plaintiff mill owner sued carrier for lost profits due to delayed delivery of broken mill shaft.",
            },
            {
                "citation": "Jacob & Youngs v. Kent, 230 N.Y. 239 (1921)",
                "holding": "Substantial performance doctrine applies where breach is minor and unintentional; damages measured by difference in value rather than cost of replacement.",
                "relevance_score": 0.89,
                "jurisdiction": "NY",
                "key_facts": "Builder used different brand of pipe than specified in contract for new home construction.",
            },
            {
                "citation": "Texaco Inc. v. Pennzoil Co., 729 S.W.2d 768 (Tex. App. 1987)",
                "holding": "Tortious interference with contractual relations established where third party intentionally disrupted binding agreement.",
                "relevance_score": 0.82,
                "jurisdiction": "TX",
                "key_facts": "Texaco induced Getty Oil to breach merger agreement with Pennzoil; $10.53 billion judgment affirmed.",
            },
        ]
    else:
        cases = [
            {
                "citation": "Celotex Corp. v. Catrett, 477 U.S. 317 (1986)",
                "holding": "Moving party on summary judgment need not negate opponent's claim but must show absence of genuine issue of material fact.",
                "relevance_score": 0.91,
                "jurisdiction": "SCOTUS",
                "key_facts": "Asbestos exposure wrongful death suit; Court clarified summary judgment burden of production.",
            },
            {
                "citation": "Ashcroft v. Iqbal, 556 U.S. 662 (2009)",
                "holding": "To survive a motion to dismiss, a complaint must contain sufficient factual matter to state a claim that is plausible on its face.",
                "relevance_score": 0.88,
                "jurisdiction": "SCOTUS",
                "key_facts": "Detainee alleged discriminatory treatment post-9/11; Court established plausibility pleading standard.",
            },
            {
                "citation": "Anderson v. Liberty Lobby, Inc., 477 U.S. 242 (1986)",
                "holding": "On summary judgment, court must view evidence in light most favorable to non-moving party and determine whether reasonable jury could find for that party.",
                "relevance_score": 0.85,
                "jurisdiction": "SCOTUS",
                "key_facts": "Defamation suit by political organization; Court defined 'genuine issue' standard for summary judgment.",
            },
        ]

    state.setdefault("case_law_searches", []).append(query)

    return {
        "query": query,
        "jurisdiction": jurisdiction,
        "date_range": date_range,
        "cases": cases,
        "holdings": [c["holding"] for c in cases],
        "relevance_score": max(c["relevance_score"] for c in cases) if cases else 0.0,
        "total_results": len(cases),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L5_case_law_db",
        tool_name="Case Law Database",
        description="Search case law databases by query, jurisdiction, and date range for precedents, holdings, and relevance.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
