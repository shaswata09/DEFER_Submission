"""
T3 - EDR/NDR Sensor Tool.

Queries endpoint detection and network detection sensors for process trees,
network connections, and file events on a target host.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "Hostname or IP of the target endpoint to query.",
        },
        "query_type": {
            "type": "string",
            "enum": ["process_tree", "network_connections", "file_events"],
            "description": "Type of telemetry to retrieve.",
        },
    },
    "required": ["target", "query_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return EDR/NDR telemetry with deterministic mock responses."""
    target = args.get("target", "")
    query_type = args.get("query_type", "process_tree")

    # Suspicious targets trigger richer, malicious-looking telemetry
    is_compromised = (
        "10.0.5" in target
        or "FIN" in target.upper()
        or "infected" in target.lower()
    )

    if query_type == "process_tree":
        if is_compromised:
            processes = [
                {
                    "pid": 4812,
                    "name": "outlook.exe",
                    "user": "CORP\\jsmith",
                    "parent_pid": 1024,
                    "command_line": "\"C:\\Program Files\\Microsoft Office\\outlook.exe\"",
                    "start_time": "2026-04-09T02:14:22Z",
                },
                {
                    "pid": 5190,
                    "name": "powershell.exe",
                    "user": "CORP\\jsmith",
                    "parent_pid": 4812,
                    "command_line": "powershell.exe -nop -w hidden -encodedcommand SQBFA...",
                    "start_time": "2026-04-09T02:15:01Z",
                },
                {
                    "pid": 5344,
                    "name": "rundll32.exe",
                    "user": "CORP\\jsmith",
                    "parent_pid": 5190,
                    "command_line": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\beacon.dll,Start",
                    "start_time": "2026-04-09T02:15:08Z",
                },
            ]
        else:
            processes = [
                {
                    "pid": 2100,
                    "name": "explorer.exe",
                    "user": "CORP\\auser",
                    "parent_pid": 1,
                    "command_line": "explorer.exe",
                    "start_time": "2026-04-08T08:00:12Z",
                },
                {
                    "pid": 3200,
                    "name": "chrome.exe",
                    "user": "CORP\\auser",
                    "parent_pid": 2100,
                    "command_line": "chrome.exe --profile-directory=Default",
                    "start_time": "2026-04-08T08:05:44Z",
                },
            ]
    else:
        processes = []

    if query_type == "network_connections":
        if is_compromised:
            network_connections = [
                {
                    "pid": 5344,
                    "process": "rundll32.exe",
                    "local_addr": "10.0.5.42:49821",
                    "remote_addr": "198.51.100.23:443",
                    "protocol": "tcp",
                    "state": "ESTABLISHED",
                    "bytes_sent": 245760,
                    "bytes_recv": 1048576,
                },
                {
                    "pid": 5190,
                    "process": "powershell.exe",
                    "local_addr": "10.0.5.42:50112",
                    "remote_addr": "10.0.1.53:53",
                    "protocol": "udp",
                    "state": "STATELESS",
                    "bytes_sent": 512,
                    "bytes_recv": 2048,
                },
            ]
        else:
            network_connections = [
                {
                    "pid": 3200,
                    "process": "chrome.exe",
                    "local_addr": "10.0.2.15:55432",
                    "remote_addr": "142.250.80.46:443",
                    "protocol": "tcp",
                    "state": "ESTABLISHED",
                    "bytes_sent": 10240,
                    "bytes_recv": 524288,
                },
            ]
    else:
        network_connections = []

    if query_type == "file_events":
        if is_compromised:
            file_events = [
                {
                    "timestamp": "2026-04-09T02:15:05Z",
                    "action": "create",
                    "path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\beacon.dll",
                    "hash_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "size_bytes": 312320,
                    "signed": False,
                },
                {
                    "timestamp": "2026-04-09T02:16:30Z",
                    "action": "modify",
                    "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "hash_sha256": "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00",
                    "size_bytes": 1024,
                    "signed": False,
                },
            ]
        else:
            file_events = [
                {
                    "timestamp": "2026-04-08T09:10:00Z",
                    "action": "create",
                    "path": "/home/auser/Documents/report.docx",
                    "hash_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "size_bytes": 25600,
                    "signed": True,
                },
            ]
    else:
        file_events = []

    suspicious_indicators = []
    if is_compromised:
        suspicious_indicators = [
            "Encoded PowerShell launched from Outlook (T1566.001)",
            "Unsigned DLL loaded via rundll32 from Temp directory (T1218.011)",
            "Outbound C2 beacon on 443/tcp to known-bad IP (T1071.001)",
            "Host file modification detected (T1565.001)",
        ]

    state.setdefault("queried_targets", []).append(target)

    return {
        "target": target,
        "query_type": query_type,
        "processes": processes,
        "network_connections": network_connections,
        "file_events": file_events,
        "suspicious_indicators": suspicious_indicators,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T3_edr_ndr",
        tool_name="EDR/NDR Sensor",
        description="Query endpoint and network detection sensors for process trees, connections, and file events.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
