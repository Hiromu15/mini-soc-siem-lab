from __future__ import annotations

import argparse
import json
from time import sleep
from urllib import error, parse, request


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def ensure_local_target(base_url: str) -> None:
    parsed = parse.urlparse(base_url)
    if parsed.hostname not in LOCAL_HOSTS:
        raise SystemExit(
            "Refusing to send demo requests to a non-local host. "
            "Use the Docker Compose nginx endpoint, for example http://localhost:8080."
        )


def http_get(url: str, user_agent: str = "mini-soc-local-demo/0.1") -> int:
    req = request.Request(url, headers={"User-Agent": user_agent}, method="GET")
    try:
        with request.urlopen(req, timeout=10) as response:
            return response.status
    except error.HTTPError as exc:
        return exc.code


def http_post_login(base_url: str, username: str, password: str) -> int:
    body = parse.urlencode({"username": username, "password": password}).encode("utf-8")
    req = request.Request(
        f"{base_url}/login",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "mini-soc-local-demo/0.1",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            return response.status
    except error.HTTPError as exc:
        return exc.code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send local-only HTTP requests to the Docker Compose demo web app."
    )
    parser.add_argument("--base-url", default="http://localhost:8080", help="Local nginx base URL.")
    parser.add_argument(
        "--pause",
        type=float,
        default=0.05,
        help="Pause between requests in seconds.",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    ensure_local_target(base_url)

    results: list[dict[str, object]] = []
    results.append({"path": "/", "status": http_get(f"{base_url}/")})

    for index in range(10):
        status = http_post_login(base_url, "admin", f"wrong-password-{index}")
        results.append({"path": "/login", "status": status})
        sleep(args.pause)

    suspicious_paths = [
        "/search?q=%27%20OR%20%271%27%3D%271",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/download?file=../../etc/passwd",
    ]
    for path in suspicious_paths:
        results.append({"path": path, "status": http_get(f"{base_url}{path}")})
        sleep(args.pause)

    for index in range(20):
        path = f"/missing-demo-path-{index}"
        results.append({"path": path, "status": http_get(f"{base_url}{path}")})
        sleep(args.pause)

    results.append(
        {
            "path": "/admin",
            "status": http_get(f"{base_url}/admin", user_agent="sqlmap/1.7 local-lab"),
        }
    )

    print(json.dumps({"target": base_url, "requests": results}, indent=2))


if __name__ == "__main__":
    main()
