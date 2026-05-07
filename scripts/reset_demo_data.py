from __future__ import annotations

import argparse
import os

import psycopg


DEFAULT_DATABASE_URL = "postgresql://soc:socpass@localhost:5432/mini_soc"


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset local demo events and alerts.")
    parser.add_argument(
        "--database-url",
        default=os.getenv("RESET_DATABASE_URL", DEFAULT_DATABASE_URL),
        help="Host-accessible PostgreSQL URL. Defaults to local Docker Compose port.",
    )
    args = parser.parse_args()

    with psycopg.connect(args.database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE alerts, auth_events, events RESTART IDENTITY;")
        conn.commit()

    print("Reset local demo alerts, auth_events, and events.")


if __name__ == "__main__":
    main()
