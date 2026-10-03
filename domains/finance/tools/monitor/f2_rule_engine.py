"""
F2 - Rule Engine.

Evaluates a transaction against fraud detection rule sets,
returning triggered rules, risk score, and recommended action.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "description": "Transaction identifier to evaluate.",
        },
        "rule_set": {
            "type": "string",
            "description": "Rule set to apply (e.g. 'standard', 'high_value', 'cross_border', 'aml').",
        },
    },
    "required": ["transaction_id"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return rule engine evaluation with deterministic mock responses."""
    transaction_id = args.get("transaction_id", "TXN-00000")
    rule_set = args.get("rule_set", "standard")

    is_high_risk = (
        "88001" in transaction_id
        or "88002" in transaction_id
        or "88003" in transaction_id
        or rule_set in ("aml", "high_value")
    )

    if is_high_risk:
        triggered_rules = [
            {
                "rule_id": "FRD-201",
                "name": "CTR Structuring Detection",
                "description": "Multiple transactions just below $10,000 reporting threshold within 24h",
                "severity": "critical",
            },
            {
                "rule_id": "FRD-305",
                "name": "Velocity Anomaly",
                "description": "Transaction frequency exceeds 3x customer baseline for rolling 1h window",
                "severity": "high",
            },
            {
                "rule_id": "AML-102",
                "name": "High-Risk Jurisdiction",
                "description": "Destination country on FATF grey/black list or OFAC sanctioned",
                "severity": "critical",
            },
            {
                "rule_id": "FRD-410",
                "name": "New Payee Large Transfer",
                "description": "Wire transfer >$5,000 to previously unseen beneficiary",
                "severity": "high",
            },
        ]
        risk_score = 94
        recommended_action = "escalate_to_investigation"
    else:
        triggered_rules = [
            {
                "rule_id": "FRD-101",
                "name": "Baseline Deviation",
                "description": "Transaction amount 1.3x above 90-day average",
                "severity": "low",
            },
        ]
        risk_score = 22
        recommended_action = "log_and_monitor"

    state.setdefault("evaluated_transactions", []).append(transaction_id)

    return {
        "transaction_id": transaction_id,
        "rule_set": rule_set,
        "triggered_rules": triggered_rules,
        "rules_triggered_count": len(triggered_rules),
        "risk_score": risk_score,
        "recommended_action": recommended_action,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F2_rule_engine",
        tool_name="Rule Engine",
        description="Evaluate a transaction against fraud detection rule sets to obtain risk scores and triggered rules.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
