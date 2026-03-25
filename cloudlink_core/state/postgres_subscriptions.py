from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class PostgresSubscriptionStore:
    """
    Minimal Postgres-backed store for subscription + plan state.

    This is intentionally narrow in scope so production billing can move off the
    SQLite volume first, without forcing an all-at-once migration of the entire
    Cloudlink state model.
    """

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresSubscriptionStore")

        import psycopg2  # type: ignore
        from psycopg2.extras import RealDictCursor  # type: ignore

        self._psycopg2 = psycopg2
        self._cursor_factory = RealDictCursor
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[Any]:
        conn = self._psycopg2.connect(self.dsn)
        try:
            yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS subscriptions (
                        id BIGSERIAL PRIMARY KEY,
                        clerk_user_id TEXT NOT NULL UNIQUE,
                        tenant_id TEXT NOT NULL DEFAULT 'default',
                        stripe_customer_id TEXT,
                        stripe_subscription_id TEXT,
                        plan TEXT NOT NULL DEFAULT 'free',
                        status TEXT NOT NULL DEFAULT 'active',
                        current_period_end TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sub_stripe_customer
                    ON subscriptions(stripe_customer_id)
                    """
                )
            conn.commit()

    def get_subscription(self, clerk_user_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM subscriptions WHERE clerk_user_id = %s",
                    (clerk_user_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None

    def get_subscription_by_customer(self, stripe_customer_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM subscriptions WHERE stripe_customer_id = %s",
                    (stripe_customer_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None

    def get_tenant_active_plan(self, tenant_id: str) -> Optional[str]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT plan
                    FROM subscriptions
                    WHERE tenant_id = %s AND status = 'active'
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (tenant_id,),
                )
                row = cur.fetchone()
                return row[0] if row else None

    def upsert_subscription(
        self,
        clerk_user_id: str,
        *,
        tenant_id: str = "default",
        stripe_customer_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
        plan: str = "free",
        status: str = "active",
        current_period_end: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = _now_iso()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO subscriptions (
                        clerk_user_id, tenant_id, stripe_customer_id, stripe_subscription_id,
                        plan, status, current_period_end, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (clerk_user_id) DO UPDATE SET
                        tenant_id = EXCLUDED.tenant_id,
                        stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, subscriptions.stripe_customer_id),
                        stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, subscriptions.stripe_subscription_id),
                        plan = EXCLUDED.plan,
                        status = EXCLUDED.status,
                        current_period_end = COALESCE(EXCLUDED.current_period_end, subscriptions.current_period_end),
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        clerk_user_id,
                        tenant_id,
                        stripe_customer_id,
                        stripe_subscription_id,
                        plan,
                        status,
                        current_period_end,
                        now,
                        now,
                    ),
                )
            conn.commit()
        return self.get_subscription(clerk_user_id) or {
            "clerk_user_id": clerk_user_id,
            "tenant_id": tenant_id,
            "plan": plan,
            "status": status,
        }

    def cancel_subscription(self, clerk_user_id: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE subscriptions
                    SET status = 'cancelled', plan = 'free', updated_at = %s
                    WHERE clerk_user_id = %s
                    """,
                    (_now_iso(), clerk_user_id),
                )
            conn.commit()
