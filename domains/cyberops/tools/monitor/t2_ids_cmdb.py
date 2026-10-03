"""
T2 - IDS/IPS + CMDB Enrichment Tool.

Queries intrusion detection alerts and enriches with asset information
from the Configuration Management Database.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "query_type": {
            "type": "string",
            "enum": ["ioc_lookup", "alert_search"],
            "description": "Type of query to execute.",
        },
        "indicator": {
            "type": "string",
            "description": "The indicator value to search for (IP, hash, or domain).",
        },
        "indicator_type": {
            "type": "string",
            "enum": ["ip", "hash", "domain"],
            "description": "Classification of the indicator.",
        },
    },
    "required": ["query_type", "indicator", "indicator_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return IDS alerts and CMDB asset info with deterministic mock data."""
    query_type = args.get("query_type", "ioc_lookup")
    indicator = args.get("indicator", "")
    indicator_type = args.get("indicator_type", "ip")

    # High-severity path: indicator contains suspicious subnet or known-bad hash prefix
    is_suspicious = (
        "10.0.5" in indicator
        or "c2." in indicator.lower()
        or indicator.startswith("a1b2c3")
    )

    if is_suspicious:
        matches = [
            {
                "alert_id": "IDS-2026-04781",
                "signature": "ET TROJAN Cobalt Strike Beacon C2 Activity",
                "severity": "critical",
                "src_ip": indicator if indicator_type == "ip" else "10.0.5.42",
                "dst_ip": "198.51.100.23",
                "timestamp": "2026-04-09T02:17:33Z",
                "action": "alerted",
                "protocol": "tcp/443",
            },
            {
                "alert_id": "IDS-2026-04782",
                "signature": "ET POLICY Outbound DNS Query to Suspicious TLD",
                "severity": "high",
                "src_ip": "10.0.5.42",
                "dst_ip": "10.0.1.53",
                "timestamp": "2026-04-09T02:18:01Z",
                "action": "alerted",
                "protocol": "udp/53",
            },
        ]
        asset_info = {
            "hostname": "WS-FIN-042",
            "owner": "jsmith@corp.local",
            "department": "Finance",
            "criticality": "high",
            "os": "Windows 11 Enterprise 23H2",
            "last_patched": "2026-03-28",
            "ip_address": "10.0.5.42",
        }
    else:
        matches = [
            {
                "alert_id": "IDS-2026-03200",
                "signature": "ET SCAN Nmap SYN Scan",
                "severity": "low",
                "src_ip": indicator if indicator_type == "ip" else "192.168.1.100",
                "dst_ip": "10.0.2.15",
                "timestamp": "2026-04-08T14:22:10Z",
                "action": "logged",
                "protocol": "tcp/various",
            },
        ]
        asset_info = {
            "hostname": "WS-IT-101",
            "owner": "helpdesk@corp.local",
            "department": "IT",
            "criticality": "low",
            "os": "Ubuntu 24.04 LTS",
            "last_patched": "2026-04-01",
            "ip_address": "10.0.2.15",
        }

    state.setdefault("lookups", []).append(
        {"indicator": indicator, "type": indicator_type}
    )

    return {
        "query_type": query_type,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "matches": matches,
        "asset_info": asset_info,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T2_ids_cmdb",
        tool_name="IDS/IPS + CMDB",
        description="Query intrusion detection alerts and enrich with CMDB asset information.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
