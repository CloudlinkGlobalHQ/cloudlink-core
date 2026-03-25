from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostgresAnalyticsStore:
    """Postgres-backed deploy-aware cost analytics state."""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresAnalyticsStore")

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
                    CREATE TABLE IF NOT EXISTS cost_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        credential_id TEXT,
                        service TEXT NOT NULL,
                        hour TEXT NOT NULL,
                        cost_usd DOUBLE PRECISION NOT NULL,
                        recorded_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_cost_snapshot_uniq
                    ON cost_snapshots(tenant_id, service, hour)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_cost_snapshot_tenant_svc
                    ON cost_snapshots(tenant_id, service, hour)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS deploy_events (
                        deploy_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        service TEXT NOT NULL,
                        version TEXT,
                        environment TEXT NOT NULL DEFAULT 'production',
                        deployed_at TEXT NOT NULL,
                        source TEXT,
                        metadata TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_deploy_tenant_service
                    ON deploy_events(tenant_id, service, deployed_at)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cost_regressions (
                        regression_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        deploy_id TEXT NOT NULL,
                        service TEXT NOT NULL,
                        baseline_cost DOUBLE PRECISION NOT NULL,
                        post_cost DOUBLE PRECISION NOT NULL,
                        change_pct DOUBLE PRECISION NOT NULL,
                        monthly_impact DOUBLE PRECISION NOT NULL,
                        detected_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        confidence TEXT NOT NULL DEFAULT 'high'
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_regression_tenant
                    ON cost_regressions(tenant_id, detected_at)
                    """
                )
                cur.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_regression_deploy_svc
                    ON cost_regressions(deploy_id, service)
                    """
                )
            conn.commit()

    def record_cost_snapshot(
        self,
        tenant_id: str,
        service: str,
        hour: str,
        cost_usd: float,
        credential_id: Optional[str] = None,
    ) -> None:
        snapshot_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cost_snapshots
                        (snapshot_id, tenant_id, credential_id, service, hour, cost_usd, recorded_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, service, hour) DO UPDATE SET
                        cost_usd = EXCLUDED.cost_usd,
                        recorded_at = EXCLUDED.recorded_at,
                        credential_id = EXCLUDED.credential_id
                    """,
                    (snapshot_id, tenant_id, credential_id, service, hour, float(cost_usd), _now_iso()),
                )
            conn.commit()

    def get_cost_baseline(
        self,
        tenant_id: str,
        service: str,
        before_hour: str,
        lookback_hours: int = 168,
    ) -> Optional[float]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT AVG(cost_usd) AS avg_cost, COUNT(*) AS n
                    FROM (
                        SELECT cost_usd
                        FROM cost_snapshots
                        WHERE tenant_id = %s
                          AND service = %s
                          AND hour < %s
                        ORDER BY hour DESC
                        LIMIT %s
                    ) baseline
                    """,
                    (tenant_id, service, before_hour, int(lookback_hours)),
                )
                row = cur.fetchone()
                if not row or int(row["n"] or 0) == 0:
                    return None
                return float(row["avg_cost"])

    def get_post_deploy_cost(
        self,
        tenant_id: str,
        service: str,
        after_hour: str,
        window_hours: int = 3,
    ) -> Optional[float]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT AVG(cost_usd) AS avg_cost, COUNT(*) AS n
                    FROM (
                        SELECT cost_usd
                        FROM cost_snapshots
                        WHERE tenant_id = %s
                          AND service = %s
                          AND hour >= %s
                        ORDER BY hour ASC
                        LIMIT %s
                    ) post_window
                    """,
                    (tenant_id, service, after_hour, int(window_hours)),
                )
                row = cur.fetchone()
                if not row or int(row["n"] or 0) == 0:
                    return None
                return float(row["avg_cost"])

    def list_cost_snapshots(
        self,
        tenant_id: str,
        service: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if service:
                    cur.execute(
                        """
                        SELECT * FROM cost_snapshots
                        WHERE tenant_id = %s AND service = %s
                        ORDER BY hour DESC
                        LIMIT %s
                        """,
                        (tenant_id, service, int(limit)),
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM cost_snapshots
                        WHERE tenant_id = %s
                        ORDER BY hour DESC
                        LIMIT %s
                        """,
                        (tenant_id, int(limit)),
                    )
                return [dict(r) for r in cur.fetchall()]

    def list_tracked_services(self, tenant_id: str) -> List[str]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT service FROM cost_snapshots
                    WHERE tenant_id = %s
                    ORDER BY service
                    """,
                    (tenant_id,),
                )
                return [r[0] for r in cur.fetchall()]

    def create_deploy_event(
        self,
        tenant_id: str,
        service: str,
        deployed_at: str,
        version: Optional[str] = None,
        environment: str = "production",
        source: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        deploy_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO deploy_events
                        (deploy_id, tenant_id, service, version, environment, deployed_at, source, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        deploy_id,
                        tenant_id,
                        service,
                        version,
                        environment,
                        deployed_at,
                        source,
                        json.dumps(metadata or {}),
                    ),
                )
            conn.commit()
        return deploy_id

    def get_deploy_event(self, deploy_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM deploy_events WHERE deploy_id = %s AND tenant_id = %s",
                    (deploy_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                result = dict(row)
                result["metadata"] = json.loads(result.get("metadata") or "{}")
                return result

    def list_deploy_events(
        self,
        tenant_id: str,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if service:
                    cur.execute(
                        """
                        SELECT * FROM deploy_events
                        WHERE tenant_id = %s AND service = %s
                        ORDER BY deployed_at DESC
                        LIMIT %s
                        """,
                        (tenant_id, service, int(limit)),
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM deploy_events
                        WHERE tenant_id = %s
                        ORDER BY deployed_at DESC
                        LIMIT %s
                        """,
                        (tenant_id, int(limit)),
                    )
                rows = []
                for row in cur.fetchall():
                    result = dict(row)
                    result["metadata"] = json.loads(result.get("metadata") or "{}")
                    rows.append(result)
                return rows

    def get_deploys_pending_analysis(
        self,
        tenant_id: str,
        min_hours_elapsed: float = 2.0,
    ) -> List[Dict[str, Any]]:
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=min_hours_elapsed)).isoformat()
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT d.*
                    FROM deploy_events d
                    WHERE d.tenant_id = %s
                      AND d.deployed_at <= %s
                      AND NOT EXISTS (
                        SELECT 1 FROM cost_regressions r
                        WHERE r.deploy_id = d.deploy_id
                          AND r.service = d.service
                      )
                    ORDER BY d.deployed_at ASC
                    """,
                    (tenant_id, cutoff_iso),
                )
                rows = []
                for row in cur.fetchall():
                    result = dict(row)
                    result["metadata"] = json.loads(result.get("metadata") or "{}")
                    rows.append(result)
                return rows

    def create_regression(
        self,
        tenant_id: str,
        deploy_id: str,
        service: str,
        baseline_cost: float,
        post_cost: float,
        change_pct: float,
        monthly_impact: float,
        confidence: str = "high",
    ) -> str:
        regression_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cost_regressions
                        (regression_id, tenant_id, deploy_id, service,
                         baseline_cost, post_cost, change_pct, monthly_impact,
                         detected_at, status, confidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', %s)
                    ON CONFLICT (deploy_id, service) DO NOTHING
                    """,
                    (
                        regression_id,
                        tenant_id,
                        deploy_id,
                        service,
                        float(baseline_cost),
                        float(post_cost),
                        round(float(change_pct), 2),
                        round(float(monthly_impact), 2),
                        _now_iso(),
                        confidence,
                    ),
                )
                created = cur.rowcount > 0
            conn.commit()
        return regression_id if created else ""

    def acknowledge_regression(self, regression_id: str, tenant_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE cost_regressions
                    SET status = 'acknowledged'
                    WHERE regression_id = %s AND tenant_id = %s AND status = 'open'
                    """,
                    (regression_id, tenant_id),
                )
                updated = cur.rowcount > 0
            conn.commit()
        return updated

    def resolve_regression(self, regression_id: str, tenant_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE cost_regressions
                    SET status = 'resolved'
                    WHERE regression_id = %s AND tenant_id = %s
                    """,
                    (regression_id, tenant_id),
                )
                updated = cur.rowcount > 0
            conn.commit()
        return updated

    def list_regressions(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if status:
                    cur.execute(
                        """
                        SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
                        FROM cost_regressions r
                        LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
                        WHERE r.tenant_id = %s AND r.status = %s
                        ORDER BY r.detected_at DESC
                        LIMIT %s
                        """,
                        (tenant_id, status, int(limit)),
                    )
                else:
                    cur.execute(
                        """
                        SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
                        FROM cost_regressions r
                        LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
                        WHERE r.tenant_id = %s
                        ORDER BY r.detected_at DESC
                        LIMIT %s
                        """,
                        (tenant_id, int(limit)),
                    )
                rows = []
                for row in cur.fetchall():
                    result = dict(row)
                    result["deploy_metadata"] = json.loads(result.get("deploy_metadata") or "{}")
                    rows.append(result)
                return rows

    def get_regression(self, regression_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
                    FROM cost_regressions r
                    LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
                    WHERE r.regression_id = %s AND r.tenant_id = %s
                    """,
                    (regression_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                result = dict(row)
                result["deploy_metadata"] = json.loads(result.get("deploy_metadata") or "{}")
                return result

    def get_current_month_spend(self, tenant_id: str, service: Optional[str] = None) -> float:
        month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if service:
                    cur.execute(
                        """
                        SELECT COALESCE(SUM(cost_usd), 0) AS total
                        FROM cost_snapshots
                        WHERE tenant_id = %s AND service = %s AND hour >= %s
                        """,
                        (tenant_id, service, month_start),
                    )
                else:
                    cur.execute(
                        """
                        SELECT COALESCE(SUM(cost_usd), 0) AS total
                        FROM cost_snapshots
                        WHERE tenant_id = %s AND hour >= %s
                        """,
                        (tenant_id, month_start),
                    )
                row = cur.fetchone()
                return float((row or {}).get("total") or 0.0)
