from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib import request


def read_json_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            items.append(value)
    return items


def post_json(url: str, payload: list[dict[str, Any]]) -> dict[str, Any]:
    if not payload:
        return {"ingested": 0, "ids": []}

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest local Docker Compose JSON log files.")
    parser.add_argument("--detector-url", default="http://localhost:8001")
    parser.add_argument("--nginx-log", type=Path, default=Path("logs/nginx/access.log"))
    parser.add_argument("--auth-log", type=Path, default=Path("logs/app/auth.log"))
    args = parser.parse_args()

    detector_url = args.detector_url.rstrip("/")
    nginx_events = read_json_lines(args.nginx_log)
    auth_events = read_json_lines(args.auth_log)

    result = {
        "nginx": post_json(f"{detector_url}/ingest/nginx", nginx_events),
        "auth": post_json(f"{detector_url}/ingest/auth", auth_events),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

