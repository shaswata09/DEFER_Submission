"""
T5 - Sandbox / Cuckoo Analysis Tool.

Submits file hashes for static and dynamic analysis in a sandboxed environment.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "file_hash": {
            "type": "string",
            "description": "SHA-256 hash of the file to analyze.",
        },
        "analysis_type": {
            "type": "string",
            "enum": ["full", "quick"],
            "description": "Analysis depth: full dynamic + static, or quick static only.",
        },
    },
    "required": ["file_hash", "analysis_type"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return sandbox analysis results with deterministic mock data."""
    file_hash = args.get("file_hash", "")
    analysis_type = args.get("analysis_type", "quick")

    # Known-bad hashes start with a1b2c3 or contain "beacon"
    is_malicious = file_hash.lower().startswith("a1b2c3") or "dead" in file_hash.lower()

    if is_malicious:
        verdict = "malicious"
        malware_family = "CobaltStrike.Beacon"
        behaviors = [
            {
                "category": "persistence",
                "description": "Creates scheduled task 'WindowsUpdate' for persistence",
                "mitre_id": "T1053.005",
            },
            {
                "category": "defense_evasion",
                "description": "Process injection into svchost.exe via NtCreateSection",
                "mitre_id": "T1055.012",
            },
            {
                "category": "command_and_control",
                "description": "HTTPS beacon to 198.51.100.23 every 60s with 25% jitter",
                "mitre_id": "T1071.001",
            },
            {
                "category": "collection",
                "description": "Keylogger module activated, captures to %TEMP%\\klog.dat",
                "mitre_id": "T1056.001",
            },
        ]
        iocs_extracted = [
            {"type": "ip", "value": "198.51.100.23", "context": "C2 server"},
            {"type": "domain", "value": "c2.update-service.xyz", "context": "DNS fallback C2"},
            {"type": "mutex", "value": "Global\\MSCTF.Asm.{b1e5}", "context": "Beacon mutex"},
            {"type": "file_path", "value": "%TEMP%\\beacon.dll", "context": "Dropped payload"},
            {"type": "registry", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SysUpdate", "context": "Persistence key"},
        ]
        risk_score = 9.6
    else:
        verdict = "clean"
        malware_family = None
        behaviors = [
            {
                "category": "benign",
                "description": "Standard DLL loading and API usage patterns",
                "mitre_id": None,
            },
        ]
        iocs_extracted = []
        risk_score = 0.8

    duration = "180s" if analysis_type == "full" else "30s"

    state.setdefault("analyzed_hashes", []).append(file_hash[:16])

    return {
        "file_hash": file_hash,
        "analysis_type": analysis_type,
        "verdict": verdict,
        "malware_family": malware_family,
        "behaviors": behaviors,
        "iocs_extracted": iocs_extracted,
        "risk_score": risk_score,
        "analysis_duration": duration,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T5_sandbox",
        tool_name="Sandbox/Cuckoo",
        description="Submit files for static and dynamic malware analysis in a sandboxed environment.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
