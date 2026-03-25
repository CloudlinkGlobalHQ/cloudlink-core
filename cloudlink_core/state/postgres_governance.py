from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class PostgresGovernanceStore:
    """Postgres-backed approval policy and budget state."""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresGovernanceStore")

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
                    CREATE TABLE IF NOT EXISTS approval_policies (
                        tenant_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        require_approval INTEGER NOT NULL DEFAULT 1,
                        auto_approve_min_confidence DOUBLE PRECISION,
                        PRIMARY KEY (tenant_id, action_type)
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS budgets (
                        budget_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        scope TEXT NOT NULL DEFAULT 'total',
                        service TEXT,
                        monthly_limit_usd DOUBLE PRECISION NOT NULL,
                        alert_thresholds TEXT NOT NULL DEFAULT '[50,80,100]',
                        action_on_breach TEXT NOT NULL DEFAULT 'alert',
                        enabled INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_budgets_tenant
                    ON budgets(tenant_id, created_at)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS budget_alerts (
                        alert_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        budget_id TEXT NOT NULL,
                        threshold_pct INTEGER NOT NULL,
                        current_spend_usd DOUBLE PRECISION NOT NULL,
                        budget_limit_usd DOUBLE PRECISION NOT NULL,
                        triggered_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_budget_alerts_tenant
                    ON budget_alerts(tenant_id, triggered_at)
                    """
                )
            conn.commit()

    def get_approval_policy(self, tenant_id: str, action_type: str) -> Dict[str, Any]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT require_approval, auto_approve_min_confidence
                    FROM approval_policies
                    WHERE tenant_id = %s AND action_type = %s
                    """,
                    (tenant_id, action_type),
                )
                row = cur.fetchone()
                if row:
                    return {
                        "require_approval": bool(row["require_approval"]),
                        "auto_approve_min_confidence": row["auto_approve_min_confidence"],
                    }
        return {"require_approval": True, "auto_approve_min_confidence": None}

    def set_approval_policy(
        self,
        tenant_id: str,
        action_type: str,
        require_approval: bool,
        auto_approve_min_confidence: Optional[float] = None,
    ) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO approval_policies
                    (tenant_id, action_type, require_approval, auto_approve_min_confidence)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id, action_type) DO UPDATE SET
                        require_approval = EXCLUDED.require_approval,
                        auto_approve_min_confidence = EXCLUDED.auto_approve_min_confidence
                    """,
                    (tenant_id, action_type, int(require_approval), auto_approve_min_confidence),
                )
            conn.commit()

    def list_approval_policies(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT action_type, require_approval, auto_approve_min_confidence
                    FROM approval_policies WHERE tenant_id = %s ORDER BY action_type
                    """,
                    (tenant_id,),
                )
                return [
                    {
                        "action_type": r["action_type"],
                        "require_approval": bool(r["require_approval"]),
                        "auto_approve_min_confidence": r["auto_approve_min_confidence"],
                    }
                    for r in cur.fetchall()
                ]

    def create_budget(
        self,
        tenant_id: str,
        *,
        name: str,
        scope: str = "total",
        service: Optional[str] = None,
        monthly_limit_usd: float,
        alert_thresholds: Optional[List[int]] = None,
        action_on_breach: str = "alert",
    ) -> Dict[str, Any]:
        budget_id = str(uuid.uuid4())
        now = _now_iso()
        thresholds = json.dumps(alert_thresholds or [50, 80, 100])
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO budgets
                    (budget_id, tenant_id, name, scope, service, monthly_limit_usd,
                     alert_thresholds, action_on_breach, enabled, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s)
                    """,
                    (
                        budget_id,
                        tenant_id,
                        name,
                        scope,
                        service,
                        monthly_limit_usd,
                        thresholds,
                        action_on_breach,
                        now,
                        now,
                    ),
                )
            conn.commit()
        return self.get_budget(budget_id, tenant_id) or {}

    def get_budget(self, budget_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM budgets WHERE budget_id = %s AND tenant_id = %s",
                    (budget_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                d = dict(row)
                d["alert_thresholds"] = json.loads(d.get("alert_thresholds") or "[]")
                return d

    def list_budgets(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    "SELECT * FROM budgets WHERE tenant_id = %s ORDER BY created_at DESC",
                    (tenant_id,),
                )
                result = []
                for r in cur.fetchall():
                    d = dict(r)
                    d["alert_thresholds"] = json.loads(d.get("alert_thresholds") or "[]")
                    result.append(d)
                return result

    def update_budget(self, budget_id: str, tenant_id: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        allowed = {"name", "monthly_limit_usd", "alert_thresholds", "action_on_breach", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return self.get_budget(budget_id, tenant_id)
        if "alert_thresholds" in updates:
            updates["alert_thresholds"] = json.dumps(updates["alert_thresholds"])
        updates["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = %s" for k in updates)
        vals = list(updates.values()) + [budget_id, tenant_id]
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE budgets SET {set_clause} WHERE budget_id = %s AND tenant_id = %s",
                    vals,
                )
            conn.commit()
        return self.get_budget(budget_id, tenant_id)

    def delete_budget(self, budget_id: str, tenant_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM budgets WHERE budget_id = %s AND tenant_id = %s",
                    (budget_id, tenant_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def record_budget_alert(
        self,
        tenant_id: str,
        budget_id: str,
        threshold_pct: int,
        current_spend: float,
        budget_limit: float,
    ) -> str:
        alert_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO budget_alerts
                    (alert_id, tenant_id, budget_id, threshold_pct, current_spend_usd, budget_limit_usd, triggered_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (alert_id, tenant_id, budget_id, threshold_pct, current_spend, budget_limit, _now_iso()),
                )
            conn.commit()
        return alert_id

    def list_budget_alerts(
        self, tenant_id: str, budget_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if budget_id:
                    cur.execute(
                        """
                        SELECT * FROM budget_alerts
                        WHERE tenant_id = %s AND budget_id = %s
                        ORDER BY triggered_at DESC LIMIT %s
                        """,
                        (tenant_id, budget_id, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM budget_alerts
                        WHERE tenant_id = %s
                        ORDER BY triggered_at DESC LIMIT %s
                        """,
                        (tenant_id, limit),
                    )
                return [dict(r) for r in cur.fetchall()]

    def get_last_budget_alert(self, tenant_id: str, budget_id: str, threshold_pct: int) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT * FROM budget_alerts
                    WHERE tenant_id = %s AND budget_id = %s AND threshold_pct = %s
                    ORDER BY triggered_at DESC LIMIT 1
                    """,
                    (tenant_id, budget_id, threshold_pct),
                )
                row = cur.fetchone()
                return dict(row) if row else None
