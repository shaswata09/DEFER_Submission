"""
T6 - SIEM Search Tool.

Executes structured queries against the Security Information and Event Management
system to retrieve correlated security events.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "SIEM search query (SPL/KQL-style).",
        },
        "time_range": {
            "type": "string",
            "enum": ["24h", "7d", "30d"],
            "description": "Time window to search within.",
        },
    },
    "required": ["query", "time_range"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return SIEM search results with deterministic mock data."""
    query = args.get("query", "")
    time_range = args.get("time_range", "24h")

    query_lower = query.lower()

    # Queries mentioning suspicious IPs or C2 indicators yield high-severity events
    is_threat_query = (
        "10.0.5" in query
        or "198.51.100" in query
        or "cobalt" in query_lower
        or "beacon" in query_lower
        or "c2" in query_lower
    )

    if is_threat_query:
        total_hits = 847
        events = [
            {
                "timestamp": "2026-04-09T02:15:01Z",
                "source_ip": "10.0.5.42",
                "dest_ip": "198.51.100.23",
                "event_type": "network_connection",
                "outcome": "allowed",
                "rule": "Outbound HTTPS to uncategorized IP",
                "user": "CORP\\jsmith",
                "host": "WS-FIN-042",
            },
            {
                "timestamp": "2026-04-09T02:15:08Z",
                "source_ip": "10.0.5.42",
                "dest_ip": "10.0.5.42",
                "event_type": "process_creation",
                "outcome": "success",
                "rule": "Suspicious rundll32 execution from Temp",
                "user": "CORP\\jsmith",
                "host": "WS-FIN-042",
            },
            {
                "timestamp": "2026-04-09T02:17:33Z",
                "source_ip": "10.0.5.42",
                "dest_ip": "198.51.100.23",
                "event_type": "ids_alert",
                "outcome": "alerted",
                "rule": "ET TROJAN Cobalt Strike Beacon C2",
                "user": "CORP\\jsmith",
                "host": "WS-FIN-042",
            },
            {
                "timestamp": "2026-04-09T02:22:45Z",
                "source_ip": "10.0.5.42",
                "dest_ip": "10.0.3.10",
                "event_type": "authentication",
                "outcome": "failure",
                "rule": "Failed Kerberos TGT request from non-DC host",
                "user": "CORP\\jsmith",
                "host": "WS-FIN-042",
            },
            {
                "timestamp": "2026-04-09T02:24:10Z",
                "source_ip": "10.0.5.42",
                "dest_ip": "10.0.5.50",
                "event_type": "smb_access",
                "outcome": "success",
                "rule": "Lateral movement via SMB to file server",
                "user": "CORP\\jsmith",
                "host": "WS-FIN-042",
            },
        ]
    else:
        total_hits = 23
        events = [
            {
                "timestamp": "2026-04-08T14:22:10Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.2.15",
                "event_type": "network_scan",
                "outcome": "blocked",
                "rule": "Port scan detected (>100 ports in 60s)",
                "user": "unknown",
                "host": "external",
            },
            {
                "timestamp": "2026-04-08T16:05:33Z",
                "source_ip": "10.0.2.15",
                "dest_ip": "10.0.1.1",
                "event_type": "authentication",
                "outcome": "success",
                "rule": "Normal login",
                "user": "CORP\\helpdesk",
                "host": "WS-IT-101",
            },
        ]

    state.setdefault("queries_run", []).append(query[:100])

    return {
        "query": query,
        "time_range": time_range,
        "total_hits": total_hits,
        "events": events,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T6_siem_search",
        tool_name="SIEM Search",
        description="Execute queries against the SIEM to retrieve correlated security events.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
