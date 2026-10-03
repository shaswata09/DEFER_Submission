"""
T7 - Code Analyzer Tool.

Performs static analysis on code snippets to identify vulnerabilities,
obfuscation techniques, and malicious patterns.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "code_snippet": {
            "type": "string",
            "description": "Source code to analyze.",
        },
        "language": {
            "type": "string",
            "enum": ["powershell", "python", "bash"],
            "description": "Programming language of the snippet.",
        },
    },
    "required": ["code_snippet", "language"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return static analysis results with deterministic mock data."""
    code_snippet = args.get("code_snippet", "")
    language = args.get("language", "python")

    code_lower = code_snippet.lower()

    vulnerabilities = []
    risk_score = 0.0

    # Detect suspicious patterns per language
    if language == "powershell":
        if "encodedcommand" in code_lower or "-enc" in code_lower:
            vulnerabilities.append({
                "type": "obfuscation",
                "severity": "critical",
                "line": 1,
                "description": "Base64-encoded command execution (common in fileless malware)",
                "mitre_id": "T1059.001",
            })
            risk_score += 3.5
        if "invoke-expression" in code_lower or "iex" in code_lower:
            vulnerabilities.append({
                "type": "code_injection",
                "severity": "high",
                "line": 1,
                "description": "Dynamic code execution via Invoke-Expression",
                "mitre_id": "T1059.001",
            })
            risk_score += 2.5
        if "downloadstring" in code_lower or "webclient" in code_lower:
            vulnerabilities.append({
                "type": "remote_payload",
                "severity": "critical",
                "line": 1,
                "description": "Remote payload download via WebClient",
                "mitre_id": "T1105",
            })
            risk_score += 3.0
        if "-windowstyle hidden" in code_lower or "-w hidden" in code_lower:
            vulnerabilities.append({
                "type": "stealth_execution",
                "severity": "medium",
                "line": 1,
                "description": "Hidden window execution to avoid user detection",
                "mitre_id": "T1564.003",
            })
            risk_score += 1.5

    elif language == "python":
        if "eval(" in code_lower or "exec(" in code_lower:
            vulnerabilities.append({
                "type": "code_injection",
                "severity": "high",
                "line": 1,
                "description": "Dynamic code execution via eval/exec",
                "mitre_id": "T1059.006",
            })
            risk_score += 2.5
        if "subprocess" in code_lower and ("shell=true" in code_lower or "popen" in code_lower):
            vulnerabilities.append({
                "type": "command_injection",
                "severity": "high",
                "line": 1,
                "description": "Shell command execution via subprocess with shell=True",
                "mitre_id": "T1059",
            })
            risk_score += 2.5
        if "socket" in code_lower and "connect" in code_lower:
            vulnerabilities.append({
                "type": "reverse_shell",
                "severity": "critical",
                "line": 1,
                "description": "Potential reverse shell via raw socket connection",
                "mitre_id": "T1059.006",
            })
            risk_score += 3.5
        if "base64" in code_lower and "decode" in code_lower:
            vulnerabilities.append({
                "type": "obfuscation",
                "severity": "medium",
                "line": 1,
                "description": "Base64 decoding of embedded payload",
                "mitre_id": "T1140",
            })
            risk_score += 1.5

    elif language == "bash":
        if "curl" in code_lower and ("| bash" in code_lower or "|bash" in code_lower or "| sh" in code_lower):
            vulnerabilities.append({
                "type": "remote_code_execution",
                "severity": "critical",
                "line": 1,
                "description": "Remote script download piped directly to shell",
                "mitre_id": "T1059.004",
            })
            risk_score += 3.5
        if "/dev/tcp/" in code_lower:
            vulnerabilities.append({
                "type": "reverse_shell",
                "severity": "critical",
                "line": 1,
                "description": "Bash reverse shell via /dev/tcp",
                "mitre_id": "T1059.004",
            })
            risk_score += 3.5
        if "chmod +s" in code_lower or "chmod 4" in code_lower:
            vulnerabilities.append({
                "type": "privilege_escalation",
                "severity": "high",
                "line": 1,
                "description": "SUID bit manipulation for privilege escalation",
                "mitre_id": "T1548.001",
            })
            risk_score += 2.5

    # Clamp risk score
    risk_score = min(round(risk_score, 1), 10.0)

    # If nothing suspicious found, return benign result
    if not vulnerabilities:
        vulnerabilities.append({
            "type": "none",
            "severity": "info",
            "line": 0,
            "description": "No known malicious patterns detected",
        })
        risk_score = 0.2

    state.setdefault("analyses", []).append(
        {"language": language, "risk_score": risk_score, "snippet_len": len(code_snippet)}
    )

    return {
        "language": language,
        "snippet_length": len(code_snippet),
        "vulnerabilities": vulnerabilities,
        "risk_score": risk_score,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T7_code_analyzer",
        tool_name="Code Analyzer",
        description="Static analysis of code snippets to detect vulnerabilities, obfuscation, and malicious patterns.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
