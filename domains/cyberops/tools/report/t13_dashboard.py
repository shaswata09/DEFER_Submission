"""
T13 - Reporting Dashboard.

Generate incident reports with timeline, severity, and summary
for stakeholder communication and post-incident review.
"""

import hashlib
import json

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_id": {
            "type": "string",
            "description": "Unique incident identifier.",
        },
        "summary": {
            "type": "string",
            "description": "Executive summary of the incident.",
        },
        "severity": {
            "type": "string",
            "description": "Severity level (e.g., critical, high, medium, low).",
        },
        "timeline": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Array of timeline event objects with timestamp and description.",
        },
    },
    "required": ["incident_id", "summary", "severity", "timeline"],
}


async def handler(args: dict, state: dict) -> dict:
    incident_id = args["incident_id"]
    summary = args["summary"]
    severity = args["severity"]
    timeline = args.get("timeline", [])

    if "reports" not in state:
        state["reports"] = []

    report_hash = hashlib.sha256(
        json.dumps({"id": incident_id, "sev": severity}, sort_keys=True).encode()
    ).hexdigest()[:8]
    report_id = f"RPT-{incident_id}-{report_hash}"

    report_record = {
        "report_id": report_id,
        "incident_id": incident_id,
        "severity": severity,
        "timeline_events": len(timeline),
    }
    state["reports"].append(report_record)
    state["actions_log"].append({
        "action": "generate_report",
        "report_id": report_id,
        "incident_id": incident_id,
    })

    return {
        "report_id": report_id,
        "incident_id": incident_id,
        "format": "html",
        "url": f"https://dashboard.internal/reports/{report_id}",
        "severity": severity,
        "summary": summary,
        "timeline_events": len(timeline),
        "status": "published",
        "message": (
            f"Incident report {report_id} published. "
            f"{len(timeline)} timeline event(s) recorded. "
            f"Severity: {severity}."
        ),
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T13_dashboard",
        tool_name="Reporting Dashboard",
        description="Generate and publish incident reports with timeline and severity.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
