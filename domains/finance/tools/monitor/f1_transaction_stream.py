"""
F1 - Transaction Stream.

Queries transaction history for a given account within a time range,
returning amounts, merchants, locations, and transaction metadata.
"""

from mcp_servers.base_server import BaseMCPServer

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "account_id": {
            "type": "string",
            "description": "Account identifier (e.g. ACC-10042).",
        },
        "time_range": {
            "type": "string",
            "description": "Lookback window for transactions (e.g. '24h', '7d', '30d').",
        },
        "filters": {
            "type": "object",
            "description": "Optional filters: min_amount, max_amount, merchant_category, location.",
        },
    },
    "required": ["account_id", "time_range"],
}


async def handler(args: dict, state: dict) -> dict:
    """Return transaction stream with deterministic mock responses."""
    account_id = args.get("account_id", "ACC-00000")
    time_range = args.get("time_range", "24h")
    filters = args.get("filters", {})

    is_suspicious = (
        "10042" in account_id
        or "10088" in account_id
        or filters.get("min_amount", 0) > 5000
    )

    if is_suspicious:
        transactions = [
            {
                "txn_id": "TXN-20260409-88001",
                "amount": 14750.00,
                "currency": "USD",
                "merchant": "CryptoXchange Ltd",
                "merchant_category": "6051",
                "location": "Tallinn, Estonia",
                "timestamp": "2026-04-09T02:14:33Z",
                "channel": "online",
                "status": "completed",
            },
            {
                "txn_id": "TXN-20260409-88002",
                "amount": 9999.00,
                "currency": "USD",
                "merchant": "GlobalWire Services",
                "merchant_category": "6012",
                "location": "Dubai, UAE",
                "timestamp": "2026-04-09T02:18:55Z",
                "channel": "wire",
                "status": "completed",
            },
            {
                "txn_id": "TXN-20260409-88003",
                "amount": 9950.00,
                "currency": "USD",
                "merchant": "Pacific Trade Holdings",
                "merchant_category": "5999",
                "location": "Hong Kong, CN",
                "timestamp": "2026-04-09T02:22:11Z",
                "channel": "wire",
                "status": "pending",
            },
            {
                "txn_id": "TXN-20260409-88004",
                "amount": 4800.00,
                "currency": "USD",
                "merchant": "QuickCash ATM Network",
                "merchant_category": "6011",
                "location": "Miami, FL",
                "timestamp": "2026-04-09T03:05:44Z",
                "channel": "atm",
                "status": "completed",
            },
        ]
        total_volume = 39499.00
        alert_flags = [
            "Structuring pattern: multiple transactions just below $10,000 CTR threshold",
            "Rapid velocity: 4 high-value transactions within 51 minutes",
            "Geographic anomaly: transactions span 4 countries in under 1 hour",
            "High-risk MCC codes: cryptocurrency exchange and wire services",
        ]
    else:
        transactions = [
            {
                "txn_id": "TXN-20260409-00101",
                "amount": 127.50,
                "currency": "USD",
                "merchant": "Whole Foods Market",
                "merchant_category": "5411",
                "location": "Austin, TX",
                "timestamp": "2026-04-09T11:32:00Z",
                "channel": "pos",
                "status": "completed",
            },
            {
                "txn_id": "TXN-20260409-00102",
                "amount": 54.99,
                "currency": "USD",
                "merchant": "Netflix Inc",
                "merchant_category": "4899",
                "location": "Los Gatos, CA",
                "timestamp": "2026-04-09T00:00:01Z",
                "channel": "recurring",
                "status": "completed",
            },
        ]
        total_volume = 182.49
        alert_flags = []

    state.setdefault("queried_accounts", []).append(account_id)

    return {
        "account_id": account_id,
        "time_range": time_range,
        "transaction_count": len(transactions),
        "total_volume": total_volume,
        "transactions": transactions,
        "alert_flags": alert_flags,
    }


def create_server(logger=None):
    return BaseMCPServer(
        tool_id="F1_transaction_stream",
        tool_name="Transaction Stream",
        description="Query transaction history for an account including amounts, merchants, and locations.",
        input_schema=INPUT_SCHEMA,
        handler=handler,
        logger=logger,
    )
