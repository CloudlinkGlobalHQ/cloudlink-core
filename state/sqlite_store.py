from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def action_key_for(resource_id: str, action_type: str, proposed_change: Optional[Dict[str, Any]]) -> str:
    raw = f"{resource_id}|{action_type}|{_stable_json(proposed_change or {})}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SQLiteStateStore:
    """
    SQLite-backed Cloudlink state store.

    Supports:
      - resources
      - execution_results (append-only history)
      - actions lifecycle
      - runs (one row per run_loop execution)
    """

    def __init__(self, db_path: str = "cloudlink.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        cur = self.conn.cursor()

        # Resources
        cur.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            resource_id TEXT PRIMARY KEY,
            payload TEXT
        )
        """)

        # Execution results (append-only)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS execution_results (
            result_id TEXT PRIMARY KEY,
            action_id TEXT NOT NULL,
            status TEXT,
            completed_at TEXT,
            resource_id TEXT,
            action_type TEXT,
            payload TEXT
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_exec_action_time
        ON execution_results(action_id, completed_at)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_exec_resource_action
        ON execution_results(resource_id, action_type)
        """)

        # Actions lifecycle
        cur.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            action_id TEXT PRIMARY KEY,
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
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_actions_status_retry
        ON actions(status, next_retry_at)
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_actions_resource
        ON actions(resource_id, action_type)
        """)

        # Runs (one row per run_loop execution)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            proposed_count INTEGER DEFAULT 0,
            claimed_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            failed_count INTEGER DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            status TEXT
        )
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_runs_started_at
        ON runs(started_at)
        """)

        self.conn.commit()

    # -----------------------------
    # Resource State
    # -----------------------------

    def ingest_event(self, event: Dict[str, Any]) -> None:
        resource_id = event.get("resource_id")
        if not resource_id:
            raise ValueError("event must contain resource_id")

        payload = json.dumps(event)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO resources (resource_id, payload)
            VALUES (?, ?)
        """, (resource_id, payload))
        self.conn.commit()

    def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT payload FROM resources WHERE resource_id = ?", (resource_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["payload"])

    def list_resources(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT payload FROM resources")
        rows = cur.fetchall()
        return [json.loads(r["payload"]) for r in rows]

    # -----------------------------
    # Execution Results (append-only)
    # -----------------------------

    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        action_id = result.get("action_id")
        if not action_id:
            raise ValueError("execution result must contain action_id")

        result_id = result.get("result_id") or str(uuid.uuid4())
        payload = json.dumps(result)

        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO execution_results
            (result_id, action_id, status, completed_at, resource_id, action_type, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result_id,
            action_id,
            result.get("status"),
            result.get("completed_at"),
            result.get("resource_id"),
            result.get("action_type"),
            payload,
        ))
        self.conn.commit()

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        """Return latest result per action_id."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT er.action_id, er.payload
            FROM execution_results er
            JOIN (
                SELECT action_id, MAX(completed_at) AS max_completed_at
                FROM execution_results
                GROUP BY action_id
            ) latest
            ON er.action_id = latest.action_id AND er.completed_at = latest.max_completed_at
        """)
        rows = cur.fetchall()

        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            out[r["action_id"]] = json.loads(r["payload"])
        return out

    def list_execution_results_for_action(self, action_id: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT payload
            FROM execution_results
            WHERE action_id = ?
            ORDER BY completed_at ASC
        """, (action_id,))
        rows = cur.fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def last_success_completed_at(self, resource_id: str, action_type: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT completed_at
            FROM execution_results
            WHERE resource_id = ? AND action_type = ? AND status = 'SUCCESS'
            ORDER BY completed_at DESC
            LIMIT 1
        """, (resource_id, action_type))
        row = cur.fetchone()
        return None if not row else row["completed_at"]

    # -----------------------------
    # Actions Lifecycle
    # -----------------------------

    def create_action_if_new(self, action: Dict[str, Any]) -> bool:
        required = ["action_id", "action_key", "action_type", "resource_id", "status", "created_at", "updated_at"]
        for k in required:
            if not action.get(k):
                raise ValueError(f"action missing required field: {k}")

        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO actions (
                    action_id, action_key, agent, action_type, resource_id, resource_type,
                    proposed_change, status, attempt_count, next_retry_at, last_error,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action["action_id"],
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
                action["created_at"],
                action["updated_at"],
            ))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def claim_actions(self, limit: int) -> List[Dict[str, Any]]:
        now = _now_iso()
        cur = self.conn.cursor()

        cur.execute("""
            SELECT action_id
            FROM actions
            WHERE status IN ('PENDING','RETRY')
              AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?
        """, (now, int(limit)))

        ids = [r["action_id"] for r in cur.fetchall()]
        if not ids:
            return []

        placeholders = ",".join("?" for _ in ids)
        cur.execute(
            f"UPDATE actions SET status='IN_PROGRESS', updated_at=? WHERE action_id IN ({placeholders})",
            (now, *ids),
        )
        self.conn.commit()

        cur.execute(f"SELECT * FROM actions WHERE action_id IN ({placeholders})", (*ids,))
        rows = cur.fetchall()

        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append({
                "action_id": r["action_id"],
                "action_key": r["action_key"],
                "agent": r["agent"],
                "action_type": r["action_type"],
                "resource_id": r["resource_id"],
                "resource_type": r["resource_type"],
                "proposed_change": json.loads(r["proposed_change"] or "{}"),
                "status": r["status"],
                "attempt_count": int(r["attempt_count"] or 0),
                "next_retry_at": r["next_retry_at"],
                "last_error": r["last_error"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return out

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

        sets = ["status = ?", "updated_at = ?"]
        params: List[Any] = [status, updated_at]

        if attempt_count is not None:
            sets.append("attempt_count = ?")
            params.append(int(attempt_count))
        if next_retry_at is not None:
            sets.append("next_retry_at = ?")
            params.append(next_retry_at)
        if last_error is not None:
            sets.append("last_error = ?")
            params.append(last_error)

        params.append(action_id)
        cur = self.conn.cursor()
        cur.execute(f"UPDATE actions SET {', '.join(sets)} WHERE action_id = ?", params)
        self.conn.commit()

    def force_retry_action(self, action_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE actions
            SET status='RETRY',
                next_retry_at=NULL,
                updated_at=?
            WHERE action_id=?
        """, (_now_iso(), action_id))
        self.conn.commit()

    # -----------------------------
    # Runs
    # -----------------------------

    def create_run(self) -> str:
        run_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO runs (run_id, started_at, status)
            VALUES (?, ?, ?)
        """, (run_id, _now_iso(), "RUNNING"))
        self.conn.commit()
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
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE runs
            SET finished_at=?,
                proposed_count=?,
                claimed_count=?,
                success_count=?,
                failed_count=?,
                retry_count=?,
                status='FINISHED'
            WHERE run_id=?
        """, (
            _now_iso(),
            int(proposed_count),
            int(claimed_count),
            int(success_count),
            int(failed_count),
            int(retry_count),
            run_id,
        ))
        self.conn.commit()

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT *
            FROM runs
            ORDER BY started_at DESC
            LIMIT ?
        """, (int(limit),))
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    # -----------------------------
    # Read Helpers (API)
    # -----------------------------

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
        r = cur.fetchone()
        if not r:
            return None
        return {
            "action_id": r["action_id"],
            "action_key": r["action_key"],
            "agent": r["agent"],
            "action_type": r["action_type"],
            "resource_id": r["resource_id"],
            "resource_type": r["resource_type"],
            "proposed_change": json.loads(r["proposed_change"] or "{}"),
            "status": r["status"],
            "attempt_count": int(r["attempt_count"] or 0),
            "next_retry_at": r["next_retry_at"],
            "last_error": r["last_error"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def list_actions(self, status: Optional[str] = None, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if status:
            cur.execute("""
                SELECT action_id FROM actions
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """, (status, int(limit), int(offset)))
        else:
            cur.execute("""
                SELECT action_id FROM actions
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """, (int(limit), int(offset)))

        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            a = self.get_action(r["action_id"])
            if a:
                out.append(a)
        return out

    def count_actions_by_status(self) -> Dict[str, int]:
        cur = self.conn.cursor()
        cur.execute("SELECT status, COUNT(*) AS n FROM actions GROUP BY status")
        rows = cur.fetchall()
        return {r["status"]: int(r["n"]) for r in rows}

    def has_active_action(self, resource_id: str, action_type: str) -> bool:
        """Return True if a PENDING, IN_PROGRESS, or RETRY action exists for this resource+type."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT COUNT(*) AS n
            FROM actions
            WHERE resource_id = ?
              AND action_type = ?
              AND status IN ('PENDING', 'IN_PROGRESS', 'RETRY')
        """, (resource_id, action_type))
        row = cur.fetchone()
        return int(row["n"]) > 0
