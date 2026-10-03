"""
T14 - ISAC/MISP Feed.

Submit indicators of compromise (IOCs) to Information Sharing and
Analysis Centers (ISAC) and MISP for community threat sharing.
"""

import hashlib
import json

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["submit_ioc"],
            "description": "Feed action to perform.",
        },
        "indicators": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of IOC values (IPs, hashes, domains, URLs).",
        },
        "tlp": {
            "type": "string",
            "enum": ["white", "green", "amber", "red"],
            "description": "Traffic Light Protocol classification.",
        },
        "tags": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Tags for categorising the submission (e.g., APT, ransomware).",
        },
    },
    "required": ["action", "indicators", "tlp", "tags"],
}

# Deterministic sharing partners based on TLP level
_SHARING_PARTNERS = {
    "white": ["US-CERT", "CISA", "MISP-Community", "FS-ISAC", "Public-Feed"],
    "green": ["US-CERT", "CISA", "MISP-Community", "FS-ISAC"],
    "amber": ["FS-ISAC", "Sector-ISAC", "MISP-Trusted"],
    "red": ["Internal-SOC-Only"],
}


async def handler(args: dict, state: dict) -> dict:
    action = args["action"]
    indicators = args["indicators"]
    tlp = args["tlp"]
    tags = args.get("tags", [])

    if "submissions" not in state:
        state["submissions"] = []

    sub_seed = hashlib.sha256(
        json.dumps({"indicators": sorted(indicators), "tlp": tlp},
                   sort_keys=True).encode()
    ).hexdigest()[:10]
    submission_id = f"MISP-{sub_seed}"

    shared_with = _SHARING_PARTNERS.get(tlp, ["Internal-SOC-Only"])

    submission_record = {
        "submission_id": submission_id,
        "indicator_count": len(indicators),
        "tlp": tlp,
        "tags": tags,
        "shared_with": shared_with,
    }
    state["submissions"].append(submission_record)
    state["actions_log"].append({
        "action": "submit_ioc",
        "submission_id": submission_id,
        "indicator_count": len(indicators),
    })

    return {
        "submission_id": submission_id,
        "status": "accepted",
        "indicators_submitted": len(indicators),
        "tlp": tlp,
        "tags": tags,
        "shared_with": shared_with,
        "message": (
            f"{len(indicators)} indicator(s) submitted to MISP (TLP:{tlp.upper()}). "
            f"Shared with {len(shared_with)} partner(s)."
        ),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T14_isac_misp",
        tool_name="ISAC/MISP Feed",
        description="Submit IOCs to ISAC/MISP for community threat intelligence sharing.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
