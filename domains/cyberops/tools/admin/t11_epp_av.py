"""
T11 - EPP/AV (Endpoint Protection Platform / Antivirus).

Trigger endpoint scans and quarantine detected threats on
target hosts during incident response.
"""

import hashlib

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["scan", "quarantine"],
            "description": "EPP action: scan an endpoint or quarantine a threat.",
        },
        "target": {
            "type": "string",
            "description": "Hostname, IP, or file path to scan/quarantine.",
        },
        "scan_type": {
            "type": "string",
            "enum": ["full", "quick"],
            "description": "Depth of the scan (full or quick).",
        },
    },
    "required": ["action", "target", "scan_type"],
}

# Deterministic mock threat database keyed by target hash prefix
_THREAT_DB = {
    "0": [],
    "1": [{"name": "Trojan.GenericKD.46789", "path": "/usr/local/bin/.hidden", "severity": "high"}],
    "2": [{"name": "Miner.CoinHive.A", "path": "/tmp/.x11-lock", "severity": "medium"}],
    "3": [
        {"name": "Backdoor.Linux.Mirai.B", "path": "/var/tmp/update", "severity": "critical"},
        {"name": "Rootkit.Linux.Agent.C", "path": "/dev/shm/.cache", "severity": "high"},
    ],
    "4": [{"name": "Ransomware.WannaCry.Gen", "path": "C:\\Users\\admin\\payload.exe", "severity": "critical"}],
    "5": [],
    "6": [{"name": "PUP.Optional.BrowserHelper", "path": "/opt/chrome/extensions/helper.so", "severity": "low"}],
    "7": [],
    "8": [{"name": "Webshell.PHP.Generic.A", "path": "/var/www/html/.shell.php", "severity": "critical"}],
    "9": [{"name": "Adware.Agent.Y", "path": "/home/user/.local/share/adhelper", "severity": "low"}],
    "a": [],
    "b": [{"name": "Exploit.CVE-2024-3094", "path": "/usr/lib/liblzma.so.5", "severity": "critical"}],
    "c": [],
    "d": [{"name": "Keylogger.Linux.Snake.D", "path": "/usr/sbin/.klogd", "severity": "high"}],
    "e": [],
    "f": [{"name": "Dropper.Linux.Agent.F", "path": "/var/spool/cron/.job", "severity": "medium"}],
}


def _threats_for_target(target: str, scan_type: str) -> list:
    """Deterministically select threats based on target hash."""
    h = hashlib.md5(target.encode()).hexdigest()
    threats = list(_THREAT_DB.get(h[0], []))
    if scan_type == "quick" and len(threats) > 1:
        threats = threats[:1]
    return threats


async def handler(args: dict, state: dict) -> dict:
    action = args["action"]
    target = args["target"]
    scan_type = args.get("scan_type", "quick")

    if "quarantined" not in state:
        state["quarantined"] = []

    if action == "scan":
        threats = _threats_for_target(target, scan_type)
        threat_names = [t["name"] for t in threats]

        state["actions_log"].append({
            "action": "scan",
            "target": target,
            "scan_type": scan_type,
            "threats_found": len(threats),
        })

        return {
            "status": "completed",
            "target": target,
            "scan_type": scan_type,
            "threats_found": len(threats),
            "threat_details": threats,
            "quarantined": [],
            "message": (
                f"{scan_type.capitalize()} scan of '{target}' complete. "
                f"{len(threats)} threat(s) detected."
            ),
        }

    elif action == "quarantine":
        threats = _threats_for_target(target, scan_type)
        quarantined_items = []
        for t in threats:
            q_entry = {
                "name": t["name"],
                "original_path": t["path"],
                "quarantine_path": f"/var/quarantine/{t['name'].replace('.', '_').lower()}",
            }
            quarantined_items.append(q_entry)
            if q_entry not in state["quarantined"]:
                state["quarantined"].append(q_entry)

        state["actions_log"].append({
            "action": "quarantine",
            "target": target,
            "quarantined_count": len(quarantined_items),
        })

        return {
            "status": "quarantined" if quarantined_items else "no_threats",
            "target": target,
            "scan_type": scan_type,
            "threats_found": len(threats),
            "quarantined": quarantined_items,
            "message": (
                f"{len(quarantined_items)} threat(s) quarantined on '{target}'."
                if quarantined_items
                else f"No threats to quarantine on '{target}'."
            ),
        }

    return {
        "status": "error",
        "target": target,
        "scan_type": scan_type,
        "threats_found": 0,
        "quarantined": [],
        "message": f"Unknown action: {action}",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T11_epp_av",
        tool_name="EPP/AV",
        description="Scan endpoints and quarantine detected threats.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
