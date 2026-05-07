from __future__ import annotations

import os
from typing import Any

import httpx


def build_alert_message(alert: dict[str, Any]) -> str:
    return (
        f"[{alert.get('severity', 'unknown').upper()}] {alert.get('title')}\n"
        f"type={alert.get('alert_type')} ip={alert.get('ip')} path={alert.get('path')}\n"
        f"recommendation={alert.get('recommendation')}"
    )


async def send_alert_notification(alert: dict[str, Any]) -> None:
    message = build_alert_message(alert)
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    slack_url = os.getenv("SLACK_WEBHOOK_URL")

    if discord_url:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(discord_url, json={"content": message})
        return

    if slack_url:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(slack_url, json={"text": message})
        return

    print(f"Notifier stdout fallback:\n{message}", flush=True)

