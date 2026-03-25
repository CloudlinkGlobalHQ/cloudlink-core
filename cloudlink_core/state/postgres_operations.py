from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class PostgresOperationStore:
    """
    Postgres-backed operational state for resources, action lifecycle, and
    execution results.
    """

    ACTIVE_STATUSES = ("PENDING", "IN_PROGRESS", "RETRY", "AWAITING_APPROVAL")

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresOperationStore")

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
                    CREATE TABLE IF NOT EXISTS resources (
                        resource_id TEXT NOT NULL,
                        tenant_id TEXT NOT NULL DEFAULT 'default',
                        payload TEXT,
                        PRIMARY KEY (resource_id, tenant_id)
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS execution_results (
                        result_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL DEFAULT 'default',
                        action_id TEXT NOT NULL,
                        status TEXT,
                        completed_at TEXT,
                        resource_id TEXT,
                        action_type TEXT,
                        payload TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_exec_action_time
                    ON execution_results(action_id, completed_at)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_exec_resource_action
                    ON execution_results(resource_id, action_type)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_exec_tenant
                    ON execution_results(tenant_id)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS actions (
                        action_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL DEFAULT 'default',
                        action_key TEXT UNIQUE NOT NULL,
                        agent TEXT,
                        action_type TEXT NOT NULL,
                        resource_id TEXT NOT NULL,
                        resource_type TEXT,
                        proposed_change TEXT,
                        status TEXT NOT NULL,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        next_retry_at TEXT,
                        last_error TEXT,
                        reason TEXT,
                        confidence DOUBLE PRECISION,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_actions_status_retry
                    ON actions(status, next_retry_at)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_actions_resource
                    ON actions(resource_id, action_type)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_actions_tenant_status
                    ON actions(tenant_id, status)
                    """
                )
            conn.commit()

    # ------------------------------------------------------------------
    # Resource state
    # ------------------------------------------------------------------

    def ingest_event(self, event: Dict[str, Any], tenant_id: str = "default") -> None:
        resource_id = event.get("resource_id")
        if not resource_id:
            raise ValueError("event must contain resource_id")
        payload = json.dumps(event)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO resources (resource_id, tenant_id, payload)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (resource_id, tenant_id) DO UPDATE SET
                        payload = EXCLUDED.payload
                    """,
                    (resource_id, tenant_id, payload),
                )
            conn.commit()

    def get_resource(self, resource_id: str, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload FROM resources WHERE resource_id = %s AND tenant_id = %s",
                    (resource_id, tenant_id),
                )
                row = cur.fetchone()
                return json.loads(row[0]) if row else None

    def list_resources(self, tenant_id: str = "default") -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload FROM resources WHERE tenant_id = %s", (tenant_id,))
                return [json.loads(r[0]) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # Execution results
    # ------------------------------------------------------------------

    def ingest_execution_result(self, result: Dict[str, Any], tenant_id: str = "default") -> None:
        action_id = result.get("action_id")
        if not action_id:
            raise ValueError("execution result must contain action_id")
        result_id = result.get("result_id") or str(uuid.uuid4())
        payload = json.dumps(result)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO execution_results
                    (result_id, tenant_id, action_id, status, completed_at, resource_id, action_type, payload)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        result_id,
                        tenant_id,
                        action_id,
                        result.get("status"),
                        result.get("completed_at"),
                        result.get("resource_id"),
                        result.get("action_type"),
                        payload,
                    ),
                )
            conn.commit()

    def list_execution_results(self, tenant_id: str = "default") -> Dict[str, Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT er.action_id, er.payload
                    FROM execution_results er
                    JOIN (
                        SELECT action_id, MAX(completed_at) AS max_completed_at
                        FROM execution_results
                        WHERE tenant_id = %s
                        GROUP BY action_id
                    ) latest ON er.action_id = latest.action_id
                             AND er.completed_at = latest.max_completed_at
                    WHERE er.tenant_id = %s
                    """,
                    (tenant_id, tenant_id),
                )
                return {r["action_id"]: json.loads(r["payload"]) for r in cur.fetchall()}

    def list_execution_results_for_action(self, action_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT payload FROM execution_results
                    WHERE action_id = %s
                    ORDER BY completed_at ASC
                    """,
                    (action_id,),
                )
                return [json.loads(r[0]) for r in cur.fetchall()]

    def last_success_completed_at(
        self, resource_id: str, action_type: str, tenant_id: str = "default"
    ) -> Optional[str]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT completed_at FROM execution_results
                    WHERE resource_id = %s AND action_type = %s AND status = 'SUCCESS' AND tenant_id = %s
                    ORDER BY completed_at DESC LIMIT 1
                    """,
                    (resource_id, action_type, tenant_id),
                )
                row = cur.fetchone()
                return row[0] if row else None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _row_to_action(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "action_id": row["action_id"],
            "tenant_id": row["tenant_id"],
            "action_key": row["action_key"],
            "agent": row.get("agent"),
            "action_type": row["action_type"],
            "resource_id": row["resource_id"],
            "resource_type": row.get("resource_type"),
            "proposed_change": json.loads(row.get("proposed_change") or "{}"),
            "status": row["status"],
            "attempt_count": int(row.get("attempt_count") or 0),
            "next_retry_at": row.get("next_retry_at"),
            "last_error": row.get("last_error"),
            "reason": row.get("reason"),
            "confidence": row.get("confidence"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_action_if_new(self, action: Dict[str, Any], tenant_id: str = "default") -> bool:
        with self._conn() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO actions (
                            action_id, tenant_id, action_key, agent, action_type, resource_id,
                            resource_type, proposed_change, status, attempt_count,
                            next_retry_at, last_error, reason, confidence, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            action["action_id"],
                            tenant_id,
                            action["action_key"],
                            action.get("agent"),
                            action["action_type"],
                            action["resource_id"],
                            action.get("resource_type"),
                            _stable_json(action.get("proposed_change") or {}),
                            action["status"],
                            int(action.get("attempt_count") or 0),
                            action.get("next_retry_at"),
                            action.get("last_error"),
                            action.get("reason"),
                            action.get("confidence"),
                            action["created_at"],
                            action["updated_at"],
                        ),
                    )
                conn.commit()
                return True
            except self._psycopg2.IntegrityError:
                conn.rollback()
                return False

    def claim_actions(self, limit: int, tenant_id: str = "default") -> List[Dict[str, Any]]:
        now = _now_iso()
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT action_id
                    FROM actions
                    WHERE tenant_id = %s
                      AND status IN ('PENDING', 'RETRY')
                      AND (next_retry_at IS NULL OR next_retry_at <= %s)
                    ORDER BY created_at ASC
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                    """,
                    (tenant_id, now, int(limit)),
                )
                ids = [r["action_id"] for r in cur.fetchall()]
                if not ids:
                    conn.commit()
                    return []

                cur.execute(
                    """
                    UPDATE actions
                    SET status = 'IN_PROGRESS', updated_at = %s
                    WHERE action_id = ANY(%s)
                    """,
                    (now, ids),
                )
                cur.execute(
                    "SELECT * FROM actions WHERE action_id = ANY(%s)",
                    (ids,),
                )
                rows = [self._row_to_action(r) for r in cur.fetchall()]
            conn.commit()
            return rows

    def update_action(
        self,
        action_id: str,
        *,
        status: str,
        updated_at: Optional[str] = None,
        attempt_count: Optional[int] = None,
        next_retry_at: Optional[str] = None,
        last_error: Optional[str] = None,
    ) -> None:
        updated_at = updated_at or _now_iso()
        sets = ["status = %s", "updated_at = %s"]
        params: List[Any] = [status, updated_at]
        if attempt_count is not None:
            sets.append("attempt_count = %s")
            params.append(int(attempt_count))
        if next_retry_at is not None:
            sets.append("next_retry_at = %s")
            params.append(next_retry_at)
        if last_error is not None:
            sets.append("last_error = %s")
            params.append(last_error)
        params.append(action_id)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE actions SET {', '.join(sets)} WHERE action_id = %s", params)
            conn.commit()

    def approve_action(self, action_id: str, tenant_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE actions SET status='PENDING', updated_at=%s
                    WHERE action_id = %s AND tenant_id = %s AND status = 'AWAITING_APPROVAL'
                    """,
                    (_now_iso(), action_id, tenant_id),
                )
                ok = cur.rowcount > 0
            conn.commit()
        return ok

    def reject_action(self, action_id: str, tenant_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE actions SET status='FAILED', updated_at=%s
                    WHERE action_id = %s AND tenant_id = %s AND status = 'AWAITING_APPROVAL'
                    """,
                    (_now_iso(), action_id, tenant_id),
                )
                ok = cur.rowcount > 0
            conn.commit()
        return ok

    def force_retry_action(self, action_id: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE actions SET status='RETRY', next_retry_at=NULL, updated_at=%s
                    WHERE action_id = %s
                    """,
                    (_now_iso(), action_id),
                )
            conn.commit()

    def has_active_action(self, resource_id: str, action_type: str, tenant_id: str = "default") -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM actions
                    WHERE resource_id = %s AND action_type = %s AND tenant_id = %s
                      AND status = ANY(%s)
                    """,
                    (resource_id, action_type, tenant_id, list(self.ACTIVE_STATUSES)),
                )
                return int(cur.fetchone()[0]) > 0

    def get_action(self, action_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if tenant_id:
                    cur.execute(
                        "SELECT * FROM actions WHERE action_id = %s AND tenant_id = %s",
                        (action_id, tenant_id),
                    )
                else:
                    cur.execute("SELECT * FROM actions WHERE action_id = %s", (action_id,))
                row = cur.fetchone()
                return self._row_to_action(row) if row else None

    def list_actions(
        self,
        status: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
        tenant_id: str = "default",
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                if status:
                    cur.execute(
                        """
                        SELECT * FROM actions
                        WHERE tenant_id = %s AND status = %s
                        ORDER BY updated_at DESC LIMIT %s OFFSET %s
                        """,
                        (tenant_id, status, int(limit), int(offset)),
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM actions
                        WHERE tenant_id = %s
                        ORDER BY updated_at DESC LIMIT %s OFFSET %s
                        """,
                        (tenant_id, int(limit), int(offset)),
                    )
                return [self._row_to_action(r) for r in cur.fetchall()]

    def count_actions_by_status(self, tenant_id: str = "default") -> Dict[str, int]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT status, COUNT(*) AS n FROM actions
                    WHERE tenant_id = %s
                    GROUP BY status
                    """,
                    (tenant_id,),
                )
                return {r["status"]: int(r["n"]) for r in cur.fetchall()}
