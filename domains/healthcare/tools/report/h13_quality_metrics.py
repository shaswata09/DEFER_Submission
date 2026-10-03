"""
H13 - Quality Metrics Tool.

Calculates and reports clinical quality measures, benchmarks,
and trends for hospital quality programs.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "metric_type": {
            "type": "string",
            "enum": ["readmission_rate", "mortality_rate", "patient_satisfaction",
                     "infection_rate", "length_of_stay", "ed_throughput",
                     "medication_errors", "fall_rate", "sepsis_bundle_compliance"],
            "description": "Type of quality metric to calculate.",
        },
        "period": {
            "type": "string",
            "description": "Reporting period (e.g. 'Q1-2026', '2026-03', 'YTD-2026').",
        },
    },
    "required": ["metric_type", "period"],
}

METRICS_DB = {
    "readmission_rate": {
        "score": 12.8, "unit": "%", "benchmark": 15.0, "national_avg": 14.2,
        "trend": "improving", "trend_data": [14.1, 13.5, 13.0, 12.8],
    },
    "mortality_rate": {
        "score": 1.2, "unit": "%", "benchmark": 2.0, "national_avg": 1.8,
        "trend": "stable", "trend_data": [1.3, 1.2, 1.2, 1.2],
    },
    "patient_satisfaction": {
        "score": 78.5, "unit": "percentile", "benchmark": 75.0, "national_avg": 72.0,
        "trend": "improving", "trend_data": [74.0, 75.5, 77.0, 78.5],
    },
    "infection_rate": {
        "score": 0.8, "unit": "per 1000 patient-days", "benchmark": 1.0, "national_avg": 0.9,
        "trend": "improving", "trend_data": [1.1, 1.0, 0.9, 0.8],
    },
    "length_of_stay": {
        "score": 4.2, "unit": "days", "benchmark": 4.5, "national_avg": 4.8,
        "trend": "stable", "trend_data": [4.3, 4.2, 4.3, 4.2],
    },
    "ed_throughput": {
        "score": 245, "unit": "minutes (median)", "benchmark": 260, "national_avg": 270,
        "trend": "improving", "trend_data": [268, 260, 252, 245],
    },
    "medication_errors": {
        "score": 2.1, "unit": "per 1000 doses", "benchmark": 3.0, "national_avg": 2.8,
        "trend": "improving", "trend_data": [2.9, 2.6, 2.3, 2.1],
    },
    "fall_rate": {
        "score": 1.5, "unit": "per 1000 patient-days", "benchmark": 2.0, "national_avg": 1.8,
        "trend": "stable", "trend_data": [1.6, 1.5, 1.5, 1.5],
    },
    "sepsis_bundle_compliance": {
        "score": 88.2, "unit": "%", "benchmark": 85.0, "national_avg": 82.0,
        "trend": "improving", "trend_data": [82.0, 84.5, 86.8, 88.2],
    },
}


async def handler(args: dict, state: dict) -> dict:
    """Return quality metrics with deterministic mock responses."""
    metric_type = args.get("metric_type", "readmission_rate")
    period = args.get("period", "Q1-2026")

    metric = METRICS_DB.get(metric_type, METRICS_DB["readmission_rate"])

    meets_benchmark = (
        metric["score"] <= metric["benchmark"]
        if metric_type in ("readmission_rate", "mortality_rate", "infection_rate",
                           "length_of_stay", "ed_throughput", "medication_errors", "fall_rate")
        else metric["score"] >= metric["benchmark"]
    )

    state["actions_log"].append(
        {"action": "quality_metrics", "metric_type": metric_type, "period": period}
    )

    return {
        "metric_type": metric_type,
        "period": period,
        "score": metric["score"],
        "unit": metric["unit"],
        "benchmark": metric["benchmark"],
        "national_average": metric["national_avg"],
        "meets_benchmark": meets_benchmark,
        "trend": metric["trend"],
        "trend_data": metric["trend_data"],
        "quartile_labels": ["Q-4 prior", "Q-3 prior", "Q-2 prior", "Current"],
        "recommendation": "Maintain current protocols." if meets_benchmark else "Improvement plan required. Review contributing factors.",
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="H13_quality_metrics",
        tool_name="Quality Metrics",
        description="Calculate and report clinical quality measures, benchmarks, and trends.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
