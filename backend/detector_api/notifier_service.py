from __future__ import annotations

import asyncio
import os

import httpx

from detector_api.notifier import send_alert_notification


async def poll_alerts() -> None:
    detector_url = os.getenv("DETECTOR_API_URL", "http://detector-api:8000").rstrip("/")
    interval = int(os.getenv("NOTIFIER_POLL_INTERVAL_SECONDS", "15"))
    notified_ids: set[int] = set()

    print("Notifier service started. Webhook delivery is optional.", flush=True)
    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{detector_url}/alerts",
                    params={"status": "open", "limit": 50},
                )
                response.raise_for_status()
                alerts = response.json()

            for alert in sorted(alerts, key=lambda item: item["id"]):
                if alert["id"] not in notified_ids:
                    await send_alert_notification(alert)
                    notified_ids.add(alert["id"])
        except Exception as exc:  # noqa: BLE001
            print(f"Notifier polling error: {exc}", flush=True)

        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(poll_alerts())
