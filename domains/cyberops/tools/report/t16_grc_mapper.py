"""
T16 - GRC Compliance Mapper.

Map security findings to regulatory and compliance framework controls
(NIST, ISO 27001, PCI-DSS, HIPAA, SOC2, CIS) for audit evidence.
"""

import hashlib

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding": {
            "type": "string",
            "description": "Description of the security finding to map.",
        },
        "frameworks": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Compliance frameworks to map against (e.g., NIST, ISO27001, PCI-DSS).",
        },
    },
    "required": ["finding", "frameworks"],
}

# Deterministic control mappings per framework
_FRAMEWORK_CONTROLS = {
    "NIST": [
        {"control": "IR-4", "title": "Incident Handling", "family": "Incident Response"},
        {"control": "IR-5", "title": "Incident Monitoring", "family": "Incident Response"},
        {"control": "SI-4", "title": "Information System Monitoring", "family": "System and Information Integrity"},
        {"control": "AU-6", "title": "Audit Review, Analysis, and Reporting", "family": "Audit and Accountability"},
        {"control": "AC-6", "title": "Least Privilege", "family": "Access Control"},
    ],
    "ISO27001": [
        {"control": "A.16.1.5", "title": "Response to Information Security Incidents", "family": "Incident Management"},
        {"control": "A.12.4.1", "title": "Event Logging", "family": "Operations Security"},
        {"control": "A.9.2.3", "title": "Management of Privileged Access Rights", "family": "Access Control"},
        {"control": "A.18.2.1", "title": "Independent Review of Information Security", "family": "Compliance"},
    ],
    "PCI-DSS": [
        {"control": "12.10.1", "title": "Incident Response Plan", "family": "Requirement 12"},
        {"control": "10.6.1", "title": "Review Logs Daily", "family": "Requirement 10"},
        {"control": "11.5", "title": "Deploy Change-Detection Mechanisms", "family": "Requirement 11"},
    ],
    "HIPAA": [
        {"control": "164.308(a)(6)", "title": "Security Incident Procedures", "family": "Administrative Safeguards"},
        {"control": "164.312(b)", "title": "Audit Controls", "family": "Technical Safeguards"},
    ],
    "SOC2": [
        {"control": "CC7.3", "title": "Detection and Monitoring", "family": "Common Criteria"},
        {"control": "CC7.4", "title": "Incident Response", "family": "Common Criteria"},
        {"control": "CC6.1", "title": "Logical and Physical Access Controls", "family": "Common Criteria"},
    ],
    "CIS": [
        {"control": "CIS-6", "title": "Maintenance, Monitoring, and Analysis of Audit Logs", "family": "CIS Controls"},
        {"control": "CIS-19", "title": "Incident Response and Management", "family": "CIS Controls"},
    ],
}


def _select_controls(finding: str, framework: str) -> list:
    """Deterministically select relevant controls based on finding hash."""
    controls = _FRAMEWORK_CONTROLS.get(framework, [])
    if not controls:
        return []
    h = hashlib.sha256(f"{finding}:{framework}".encode()).hexdigest()
    # Select 1-3 controls deterministically
    count = (int(h[0], 16) % 3) + 1
    count = min(count, len(controls))
    indices = []
    for i in range(count):
        idx = int(h[i + 1], 16) % len(controls)
        if idx not in indices:
            indices.append(idx)
    return [controls[i] for i in indices]


async def handler(args: dict, state: dict) -> dict:
    finding = args["finding"]
    frameworks = args["frameworks"]

    if "mapping_history" not in state:
        state["mapping_history"] = []

    mappings = []
    for fw in frameworks:
        selected = _select_controls(finding, fw)
        for ctrl in selected:
            mappings.append({
                "framework": fw,
                "control": ctrl["control"],
                "title": ctrl["title"],
                "family": ctrl["family"],
                "status": "applicable",
            })

    mapping_hash = hashlib.sha256(
        f"{finding}:{'|'.join(sorted(frameworks))}".encode()
    ).hexdigest()[:8]

    record = {
        "mapping_id": f"GRC-{mapping_hash}",
        "finding": finding[:80],
        "frameworks": frameworks,
        "controls_mapped": len(mappings),
    }
    state["mapping_history"].append(record)
    state["actions_log"].append({
        "action": "map_finding",
        "mapping_id": record["mapping_id"],
        "controls_mapped": len(mappings),
    })

    return {
        "mapping_id": record["mapping_id"],
        "finding": finding,
        "frameworks_requested": frameworks,
        "mappings": mappings,
        "total_controls_mapped": len(mappings),
        "message": (
            f"Finding mapped to {len(mappings)} control(s) across "
            f"{len(frameworks)} framework(s)."
        ),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T16_grc_mapper",
        tool_name="GRC Compliance Mapper",
        description="Map security findings to compliance framework controls for audit evidence.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
