from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class PostgresRunStore:
    """Minimal Postgres-backed run history store."""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresRunStore")

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
                    CREATE TABLE IF NOT EXISTS runs (
                        run_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL DEFAULT 'default',
                        started_at TEXT NOT NULL,
                        finished_at TEXT,
                        proposed_count INTEGER DEFAULT 0,
                        claimed_count INTEGER DEFAULT 0,
                        success_count INTEGER DEFAULT 0,
                        failed_count INTEGER DEFAULT 0,
                        retry_count INTEGER DEFAULT 0,
                        status TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_runs_tenant_started
                    ON runs(tenant_id, started_at)
                    """
                )
            conn.commit()

    def create_run(self, tenant_id: str = "default") -> str:
        run_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO runs (run_id, tenant_id, started_at, status)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (run_id, tenant_id, _now_iso(), "RUNNING"),
                )
            conn.commit()
        return run_id

    def finish_run(
        self,
        run_id: str,
        *,
        proposed_count: int,
        claimed_count: int,
        success_count: int,
        failed_count: int,
        retry_count: int,
    ) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE runs
                    SET finished_at=%s, proposed_count=%s, claimed_count=%s,
                        success_count=%s, failed_count=%s, retry_count=%s, status='FINISHED'
                    WHERE run_id=%s
                    """,
                    (
                        _now_iso(),
                        int(proposed_count),
                        int(claimed_count),
                        int(success_count),
                        int(failed_count),
                        int(retry_count),
                        run_id,
                    ),
                )
            conn.commit()

    def list_runs(self, limit: int = 50, tenant_id: str = "default") -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT * FROM runs
                    WHERE tenant_id = %s
                    ORDER BY started_at DESC
                    LIMIT %s
                    """,
                    (tenant_id, int(limit)),
                )
                return [dict(r) for r in cur.fetchall()]
