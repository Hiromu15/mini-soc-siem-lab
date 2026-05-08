from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from typing import Any

from detector_api.database import SessionLocal
from detector_api.detection.engine import run_detection, seed_detection_rules


_STATE: dict[str, Any] = {
    "running": False,
    "last_run_at": None,
    "last_created_alerts": 0,
    "last_error": None,
}


def is_detection_scheduler_enabled() -> bool:
    value = os.getenv("DETECTION_SCHEDULER_ENABLED", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def get_detection_interval_seconds() -> int:
    raw_value = os.getenv("DETECTION_INTERVAL_SECONDS", "30")
    try:
        interval = int(raw_value)
    except ValueError:
        interval = 30
    return max(interval, 5)


def get_detection_scheduler_status() -> dict[str, Any]:
    return {
        "enabled": is_detection_scheduler_enabled(),
        "running": _STATE["running"],
        "interval_seconds": get_detection_interval_seconds(),
        "last_run_at": _STATE["last_run_at"],
        "last_created_alerts": _STATE["last_created_alerts"],
        "last_error": _STATE["last_error"],
    }


async def detection_scheduler_loop() -> None:
    interval_seconds = get_detection_interval_seconds()
    _STATE["running"] = True
    _STATE["last_error"] = None
    print(
        f"Detection scheduler started. interval_seconds={interval_seconds}",
        flush=True,
    )

    try:
        while True:
            await run_detection_once()
            await asyncio.sleep(interval_seconds)
    finally:
        _STATE["running"] = False
        print("Detection scheduler stopped.", flush=True)


async def run_detection_once() -> None:
    try:
        with SessionLocal() as db:
            seed_detection_rules(db)
            alerts = run_detection(db)

        _STATE["last_run_at"] = datetime.now(UTC).isoformat()
        _STATE["last_created_alerts"] = len(alerts)
        _STATE["last_error"] = None
        if alerts:
            print(f"Detection scheduler created {len(alerts)} alert(s).", flush=True)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        _STATE["last_run_at"] = datetime.now(UTC).isoformat()
        _STATE["last_created_alerts"] = 0
        _STATE["last_error"] = str(exc)
        print(f"Detection scheduler error: {exc}", flush=True)

