"""
T1 - UEBA (User and Entity Behavior Analytics) Model.

Analyzes user/entity behavior against learned baselines to detect anomalies.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "alert_data": {
            "type": "object",
            "description": "Alert payload containing user, entity, and event details.",
        },
        "time_range": {
            "type": "string",
            "description": "Lookback window for baseline comparison (e.g. '24h', '7d', '30d').",
        },
    },
    "required": ["alert_data", "time_range"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return UEBA anomaly analysis with deterministic mock responses."""
    alert_data = args.get("alert_data", {})
    time_range = args.get("time_range", "24h")
    user = alert_data.get("user", "unknown_user")
    event_type = alert_data.get("event_type", "generic")

    # Deterministic: privileged-access or admin users get high scores
    is_high_risk = (
        "admin" in user.lower()
        or "priv" in event_type.lower()
        or alert_data.get("failed_logins", 0) > 5
    )

    if is_high_risk:
        anomaly_score = 0.92
        risk_label = "critical"
        behavioral_indicators = [
            "Unusual login time (03:14 UTC, baseline 08:00-18:00 UTC)",
            "Access from previously unseen geolocation (VPN exit node, Bucharest)",
            "Lateral movement pattern: 4 hosts accessed within 12 minutes",
            "Privilege escalation attempt detected on DC-PROD-01",
        ]
        baseline_deviation = {
            "login_time_zscore": 3.8,
            "geo_anomaly": True,
            "session_duration_ratio": 4.2,
            "resource_access_count": 47,
            "baseline_resource_access_avg": 8,
        }
    else:
        anomaly_score = 0.35
        risk_label = "low"
        behavioral_indicators = [
            "Slightly elevated file access volume (1.5x baseline)",
            "Access within normal business hours",
        ]
        baseline_deviation = {
            "login_time_zscore": 0.4,
            "geo_anomaly": False,
            "session_duration_ratio": 1.1,
            "resource_access_count": 12,
            "baseline_resource_access_avg": 8,
        }

    state.setdefault("analyzed_users", []).append(user)

    return {
        "anomaly_score": anomaly_score,
        "risk_label": risk_label,
        "behavioral_indicators": behavioral_indicators,
        "baseline_deviation": baseline_deviation,
        "user": user,
        "time_range": time_range,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T1_ueba",
        tool_name="UEBA Model",
        description="Analyze user/entity behavior against learned baselines to score anomaly risk.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
