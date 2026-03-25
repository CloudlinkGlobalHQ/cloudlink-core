from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class PostgresIntegrationStore:
    """Postgres-backed scan history and webhook metadata store."""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresIntegrationStore")

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
                    CREATE TABLE IF NOT EXISTS scan_history (
                        scan_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        credential_id TEXT,
                        credential_label TEXT,
                        regions TEXT,
                        started_at TEXT NOT NULL,
                        finished_at TEXT,
                        status TEXT NOT NULL DEFAULT 'running',
                        events_found INTEGER DEFAULT 0,
                        events_ingested INTEGER DEFAULT 0,
                        actions_queued INTEGER DEFAULT 0,
                        error TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_scans_tenant
                    ON scan_history(tenant_id, started_at)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS webhooks (
                        webhook_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        url TEXT NOT NULL,
                        secret TEXT,
                        events TEXT NOT NULL DEFAULT '["action.created","action.completed","scan.finished"]',
                        enabled INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        last_fired_at TEXT,
                        last_status TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_webhooks_tenant
                    ON webhooks(tenant_id)
                    """
                )
            conn.commit()

    def create_scan(
        self,
        tenant_id: str,
        credential_id: Optional[str] = None,
        credential_label: Optional[str] = None,
        regions: Optional[List[str]] = None,
    ) -> str:
        scan_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scan_history
                    (scan_id, tenant_id, credential_id, credential_label, regions, started_at, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'running')
                    """,
                    (
                        scan_id,
                        tenant_id,
                        credential_id,
                        credential_label,
                        json.dumps(regions or []),
                        _now_iso(),
                    ),
                )
            conn.commit()
        return scan_id

    def finish_scan(
        self,
        scan_id: str,
        *,
        events_found: int = 0,
        events_ingested: int = 0,
        actions_queued: int = 0,
        error: Optional[str] = None,
    ) -> None:
        status = "error" if error else "finished"
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_history
                    SET finished_at=%s, status=%s, events_found=%s, events_ingested=%s, actions_queued=%s, error=%s
                    WHERE scan_id=%s
                    """,
                    (_now_iso(), status, events_found, events_ingested, actions_queued, error, scan_id),
                )
            conn.commit()

    def list_scans(self, tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT * FROM scan_history
                    WHERE tenant_id = %s
                    ORDER BY started_at DESC
                    LIMIT %s
                    """,
                    (tenant_id, int(limit)),
                )
                rows = []
                for r in cur.fetchall():
                    d = dict(r)
                    try:
                        d["regions"] = json.loads(d["regions"] or "[]")
                    except Exception:
                        d["regions"] = []
                    rows.append(d)
                return rows

    def add_webhook(
        self,
        tenant_id: str,
        url: str,
        secret: Optional[str] = None,
        events: Optional[List[str]] = None,
    ) -> str:
        webhook_id = str(uuid.uuid4())
        default_events = ["action.created", "action.completed", "scan.finished"]
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO webhooks (webhook_id, tenant_id, url, secret, events, enabled, created_at)
                    VALUES (%s, %s, %s, %s, %s, 1, %s)
                    """,
                    (webhook_id, tenant_id, url, secret, json.dumps(events or default_events), _now_iso()),
                )
            conn.commit()
        return webhook_id

    def list_webhooks(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM webhooks WHERE tenant_id = %s ORDER BY created_at",
                    (tenant_id,),
                )
                rows = []
                for r in cur.fetchall():
                    d = dict(r)
                    try:
                        d["events"] = json.loads(d["events"] or "[]")
                    except Exception:
                        d["events"] = []
                    rows.append(d)
                return rows

    def delete_webhook(self, tenant_id: str, webhook_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM webhooks WHERE webhook_id = %s AND tenant_id = %s",
                    (webhook_id, tenant_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def update_webhook_status(self, webhook_id: str, status: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE webhooks SET last_fired_at=%s, last_status=%s WHERE webhook_id=%s",
                    (_now_iso(), status, webhook_id),
                )
            conn.commit()
