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


def normalize_nginx_log(item: dict[str, Any]) -> dict[str, Any]:
    request = str(item.get("request") or "")
    request_parts = request.split()

    method = item.get("method") or item.get("request_method")
    path = item.get("path") or item.get("uri") or item.get("request_uri")
    if request_parts:
        method = method or request_parts[0]
    if len(request_parts) >= 2:
        path = path or request_parts[1]

    status = item.get("status_code", item.get("status"))
    try:
        status_code = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_code = None

    return {
        "timestamp": parse_timestamp(item.get("timestamp") or item.get("time")),
        "source": str(item.get("source") or "nginx"),
        "ip": str(item.get("ip") or item.get("remote_addr") or item.get("client_ip") or "unknown"),
        "method": str(method) if method else None,
        "path": str(path) if path else None,
        "status_code": status_code,
        "user_agent": str(item.get("user_agent") or item.get("http_user_agent") or ""),
        "event_type": str(item.get("event_type") or "http_access"),
        "raw_data": item,
    }

