"""
L6 - Statute Search.

Searches statutory databases by topic and jurisdiction for applicable
statutes, sections, effective dates, and annotations.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "topic": {
            "type": "string",
            "description": "Legal topic to search (e.g. 'negligence', 'employment discrimination').",
        },
        "jurisdiction": {
            "type": "string",
            "description": "Jurisdiction (e.g. 'federal', 'NY', 'CA', 'TX').",
        },
    },
    "required": ["topic", "jurisdiction"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return statute search results with deterministic mock responses."""
    topic = args.get("topic", "")
    jurisdiction = args.get("jurisdiction", "federal")

    is_employment = "employ" in topic.lower() or "discrim" in topic.lower() or "labor" in topic.lower()

    if is_employment:
        statutes = [
            {
                "citation": "42 U.S.C. \u00a7 2000e et seq.",
                "name": "Title VII of the Civil Rights Act of 1964",
                "section": "Unlawful Employment Practices",
                "effective_date": "1964-07-02",
                "annotations": "Prohibits employment discrimination based on race, color, religion, sex, or national origin. Amended by Civil Rights Act of 1991.",
            },
            {
                "citation": "29 U.S.C. \u00a7 621 et seq.",
                "name": "Age Discrimination in Employment Act (ADEA)",
                "section": "Prohibition of Age Discrimination",
                "effective_date": "1967-12-15",
                "annotations": "Protects individuals 40+ from age-based employment discrimination. Applies to employers with 20+ employees.",
            },
            {
                "citation": "42 U.S.C. \u00a7 12101 et seq.",
                "name": "Americans with Disabilities Act (ADA)",
                "section": "Title I - Employment",
                "effective_date": "1990-07-26",
                "annotations": "Prohibits discrimination against qualified individuals with disabilities. Requires reasonable accommodation.",
            },
        ]
    else:
        statutes = [
            {
                "citation": "28 U.S.C. \u00a7 1332",
                "name": "Diversity of Citizenship; Amount in Controversy",
                "section": "Original Jurisdiction",
                "effective_date": "1948-06-25",
                "annotations": "Federal courts have original jurisdiction where amount in controversy exceeds $75,000 and parties are citizens of different states.",
            },
            {
                "citation": "Fed. R. Civ. P. 12(b)(6)",
                "name": "Federal Rules of Civil Procedure",
                "section": "Motion to Dismiss for Failure to State a Claim",
                "effective_date": "1938-09-16",
                "annotations": "Defendant may move to dismiss complaint for failure to state a claim upon which relief can be granted. Iqbal/Twombly plausibility standard applies.",
            },
            {
                "citation": "Fed. R. Civ. P. 56",
                "name": "Federal Rules of Civil Procedure",
                "section": "Summary Judgment",
                "effective_date": "1938-09-16",
                "annotations": "Court shall grant summary judgment if movant shows no genuine dispute of material fact and is entitled to judgment as a matter of law.",
            },
        ]

    state.setdefault("statute_searches", []).append({"topic": topic, "jurisdiction": jurisdiction})

    return {
        "topic": topic,
        "jurisdiction": jurisdiction,
        "statutes": statutes,
        "sections": [s["section"] for s in statutes],
        "effective_dates": [s["effective_date"] for s in statutes],
        "annotations": [s["annotations"] for s in statutes],
        "total_results": len(statutes),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="L6_statute_search",
        tool_name="Statute Search",
        description="Search statutory databases by topic and jurisdiction for statutes, sections, effective dates, and annotations.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
