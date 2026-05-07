from datetime import UTC, datetime
from typing import Any


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not value:
        return datetime.now(UTC)

    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(UTC)


def normalize_auth_log(item: dict[str, Any]) -> dict[str, Any]:
    success = item.get("success", False)
    if isinstance(success, str):
        success = success.strip().lower() in {"1", "true", "yes", "success", "succeeded"}

    return {
        "timestamp": parse_timestamp(item.get("timestamp") or item.get("time")),
        "ip": str(item.get("ip") or item.get("remote_addr") or item.get("client_ip") or "unknown"),
        "username": item.get("username"),
        "success": bool(success),
        "reason": item.get("reason"),
        "raw_data": item,
    }

