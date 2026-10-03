"""
T15 - Detection Rule Editor & Test Suite.

Validate and deploy detection rules (Sigma, YARA, Snort) with
automated testing against sample data for false-positive analysis.
"""

import hashlib

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_content": {
            "type": "string",
            "description": "The detection rule source text.",
        },
        "rule_type": {
            "type": "string",
            "enum": ["sigma", "yara", "snort"],
            "description": "Type/language of the detection rule.",
        },
        "action": {
            "type": "string",
            "enum": ["validate", "deploy"],
            "description": "Whether to validate or deploy the rule.",
        },
    },
    "required": ["rule_content", "rule_type", "action"],
}

# Deterministic validation results based on rule content hash
_VALIDATION_PROFILES = [
    {"valid": True, "matches_test_data": 12, "false_positives": 0, "recommendation": "Rule is production-ready. No false positives in test corpus."},
    {"valid": True, "matches_test_data": 8, "false_positives": 1, "recommendation": "Minor tuning recommended. 1 false positive detected in benign log samples."},
    {"valid": True, "matches_test_data": 23, "false_positives": 3, "recommendation": "Consider tightening conditions. 3 false positives may cause alert fatigue."},
    {"valid": True, "matches_test_data": 5, "false_positives": 0, "recommendation": "Rule validates cleanly. Low match count suggests narrow but precise detection."},
    {"valid": False, "matches_test_data": 0, "false_positives": 0, "recommendation": "Syntax error detected. Check field names and logical operators."},
]


async def handler(args: dict, state: dict) -> dict:
    rule_content = args["rule_content"]
    rule_type = args["rule_type"]
    action = args["action"]

    if "deployed_rules" not in state:
        state["deployed_rules"] = []

    rule_hash = hashlib.sha256(rule_content.encode()).hexdigest()
    profile_idx = int(rule_hash[0], 16) % len(_VALIDATION_PROFILES)
    profile = _VALIDATION_PROFILES[profile_idx]

    rule_id = f"DET-{rule_type.upper()}-{rule_hash[:8]}"

    if action == "validate":
        state["actions_log"].append({
            "action": "validate",
            "rule_id": rule_id,
            "rule_type": rule_type,
            "valid": profile["valid"],
        })

        return {
            "rule_id": rule_id,
            "rule_type": rule_type,
            "action": "validate",
            "valid": profile["valid"],
            "matches_test_data": profile["matches_test_data"],
            "false_positives": profile["false_positives"],
            "recommendation": profile["recommendation"],
            "message": (
                f"Validation of {rule_type} rule {rule_id}: "
                f"{'PASSED' if profile['valid'] else 'FAILED'}. "
                f"{profile['matches_test_data']} match(es), "
                f"{profile['false_positives']} false positive(s)."
            ),
        }

    elif action == "deploy":
        if not profile["valid"]:
            return {
                "rule_id": rule_id,
                "rule_type": rule_type,
                "action": "deploy",
                "valid": False,
                "matches_test_data": 0,
                "false_positives": 0,
                "recommendation": "Cannot deploy: rule failed validation. Fix syntax errors first.",
                "message": f"Deployment blocked for {rule_id}: rule is invalid.",
            }

        deploy_record = {
            "rule_id": rule_id,
            "rule_type": rule_type,
            "status": "deployed",
        }
        state["deployed_rules"].append(deploy_record)
        state["actions_log"].append({
            "action": "deploy",
            "rule_id": rule_id,
            "rule_type": rule_type,
        })

        return {
            "rule_id": rule_id,
            "rule_type": rule_type,
            "action": "deploy",
            "valid": True,
            "matches_test_data": profile["matches_test_data"],
            "false_positives": profile["false_positives"],
            "recommendation": f"Rule deployed successfully. {profile['recommendation']}",
            "message": f"Rule {rule_id} ({rule_type}) deployed to detection pipeline.",
        }

    return {
        "rule_id": rule_id,
        "rule_type": rule_type,
        "action": action,
        "valid": False,
        "matches_test_data": 0,
        "false_positives": 0,
        "recommendation": f"Unknown action: {action}",
        "message": f"Error: unknown action '{action}'.",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="T15_editor_test",
        tool_name="Detection Rule Editor & Test Suite",
        description="Validate and deploy Sigma, YARA, and Snort detection rules with test coverage.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
