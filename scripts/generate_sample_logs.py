from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib import request


def build_sample_logs() -> dict[str, list[dict[str, Any]]]:
    now = datetime.now(UTC).replace(microsecond=0)
    brute_force_ip = "198.51.100.23"
    directory_scan_ip = "203.0.113.50"
    scanner_ip = "192.0.2.44"

    auth_events = [
        {
            "timestamp": (now - timedelta(seconds=240 - index * 20)).isoformat(),
            "ip": brute_force_ip,
            "username": "admin",
            "success": False,
            "reason": "invalid_credentials",
        }
        for index in range(10)
    ]

    nginx_events = [
        {
            "timestamp": (now - timedelta(seconds=180)).isoformat(),
            "source": "nginx",
            "ip": scanner_ip,
            "method": "GET",
            "path": "/search?q=%27%20OR%20%271%27%3D%271",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 demo-browser",
        },
        {
            "timestamp": (now - timedelta(seconds=150)).isoformat(),
            "source": "nginx",
            "ip": scanner_ip,
            "method": "GET",
            "path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 demo-browser",
        },
        {
            "timestamp": (now - timedelta(seconds=120)).isoformat(),
            "source": "nginx",
            "ip": scanner_ip,
            "method": "GET",
            "path": "/download?file=../../etc/passwd",
            "status_code": 404,
            "user_agent": "Mozilla/5.0 demo-browser",
        },
        {
            "timestamp": (now - timedelta(seconds=90)).isoformat(),
            "source": "nginx",
            "ip": scanner_ip,
            "method": "GET",
            "path": "/admin",
            "status_code": 401,
            "user_agent": "sqlmap/1.7 local-lab",
        },
    ]

    nginx_events.extend(
        {
            "timestamp": (now - timedelta(seconds=260 - index * 10)).isoformat(),
            "source": "nginx",
            "ip": directory_scan_ip,
            "method": "GET",
            "path": f"/missing-demo-path-{index}",
            "status_code": 404,
            "user_agent": "Mozilla/5.0 demo-browser",
        }
        for index in range(20)
    )

    return {"nginx": nginx_events, "auth": auth_events}


def post_json(url: str, payload: list[dict[str, Any]]) -> dict[str, Any]:
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
    parser = argparse.ArgumentParser(description="Generate dummy Mini SOC/SIEM sample logs.")
    parser.add_argument("--output", type=Path, help="Write generated sample logs to a JSON file.")
    parser.add_argument(
        "--send",
        action="store_true",
        help="Send logs to the detector API ingest endpoints.",
    )
    parser.add_argument(
        "--detector-url",
        default="http://localhost:8001",
        help="Detector API base URL.",
    )
    args = parser.parse_args()

    logs = build_sample_logs()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(logs, indent=2), encoding="utf-8")
        print(f"Wrote dummy sample logs to {args.output}")

    if args.send:
        detector_url = args.detector_url.rstrip("/")
        nginx_result = post_json(f"{detector_url}/ingest/nginx", logs["nginx"])
        auth_result = post_json(f"{detector_url}/ingest/auth", logs["auth"])
        print(json.dumps({"nginx": nginx_result, "auth": auth_result}, indent=2))

    if not args.output and not args.send:
        print(json.dumps(logs, indent=2))


if __name__ == "__main__":
    main()
