from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse


AUTH_LOG_PATH = Path(os.getenv("AUTH_LOG_PATH", "/var/log/vulnerable-web-app/auth.log"))
AUTH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("vulnerable-web-app")

app = FastAPI(title="Local Vulnerable Web App Simulator", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "vulnerable-web-app"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
    <html>
      <head><title>Mini SOC SIEM Lab</title></head>
      <body>
        <h1>Mini SOC SIEM Lab</h1>
        <p>This local-only app emits authentication logs for detection testing.</p>
        <p><a href="/login">Login</a></p>
      </body>
    </html>
    """


@app.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return """
    <html>
      <head><title>Login</title></head>
      <body>
        <h1>Login</h1>
        <form method="post" action="/login">
          <label>Username <input name="username" /></label>
          <label>Password <input name="password" type="password" /></label>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.post("/login")
async def login(request: Request) -> JSONResponse:
    credentials = await _read_credentials(request)
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    success = username == "admin" and password == "password123"
    reason = "valid_demo_credentials" if success else "invalid_credentials"

    auth_event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "ip": _client_ip(request),
        "username": username,
        "success": success,
        "reason": reason,
        "source": "vulnerable-web-app",
    }
    _write_auth_log(auth_event)

    status_code = status.HTTP_200_OK if success else status.HTTP_401_UNAUTHORIZED
    return JSONResponse(
        status_code=status_code,
        content={"success": success, "message": "login accepted" if success else "login failed"},
    )


@app.get("/admin")
def admin(request: Request) -> JSONResponse:
    if request.headers.get("x-demo-admin") == "true":
        return JSONResponse({"message": "local admin demo area"})
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "not authenticated"},
    )


@app.get("/search")
def search(q: str = "") -> dict[str, str]:
    return {"query": q, "message": "Search is intentionally inert and returns JSON only."}


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> Response:  # noqa: ARG001
    return JSONResponse(status_code=404, content={"detail": "not found", "path": request.url.path})


async def _read_credentials(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
        return {
            "username": str(data.get("username", "")),
            "password": str(data.get("password", "")),
        }

    raw_body = (await request.body()).decode("utf-8", errors="replace")
    parsed = parse_qs(raw_body)
    return {
        "username": parsed.get("username", [""])[0],
        "password": parsed.get("password", [""])[0],
    }


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _write_auth_log(auth_event: dict[str, object]) -> None:
    line = json.dumps(auth_event, ensure_ascii=True)
    logger.info(line)
    with AUTH_LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{line}\n")
