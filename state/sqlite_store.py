from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class SQLiteStateStore:
    """
    SQLite-backed implementation of the StateStore contract.
    """

    def __init__(self, db_path: str = "cloudlink.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    # -------------------------
    # Table creation
    # -------------------------
    def _create_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            resource_id TEXT PRIMARY KEY,
            payload TEXT
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS execution_results (
            action_id TEXT PRIMARY KEY,
            status TEXT,
            completed_at TEXT,
            resource_id TEXT,
            action_type TEXT,
            payload TEXT
        )
        """)

        # helpful index for agent suppression queries
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_exec_resource_action
        ON execution_results(resource_id, action_type)
        """)

        self.conn.commit()

    # -------------------------
    # Events / Resources
    # -------------------------
    def ingest_event(self, event: Dict[str, Any]) -> None:
        rid = event.get("resource_id")
        if not rid:
            raise ValueError("event must contain resource_id")

        payload = json.dumps(event)

        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO resources (resource_id, payload)
            VALUES (?, ?)
        """, (rid, payload))
        self.conn.commit()

    def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT payload FROM resources WHERE resource_id = ?",
            (resource_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["payload"])

    def list_resources(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT payload FROM resources")
        return [json.loads(r["payload"]) for r in cur.fetchall()]

    # -------------------------
    # Execution Results
    # -------------------------
    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        aid = result.get("action_id")
        if not aid:
            raise ValueError("execution result must contain action_id")

        payload = json.dumps(result)

        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO execution_results
            (action_id, status, completed_at, resource_id, action_type, payload)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            aid,
            result.get("status"),
            result.get("completed_at"),
            result.get("resource_id"),
            result.get("action_type"),
            payload,
        ))
        self.conn.commit()

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT action_id, payload FROM execution_results")

        out: Dict[str, Dict[str, Any]] = {}
        for r in cur.fetchall():
            out[r["action_id"]] = json.loads(r["payload"])
        return out

    # -------------------------
    # Helper for agents
    # -------------------------
    def last_status(self, resource_id: str, action_type: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT status
            FROM execution_results
            WHERE resource_id = ? AND action_type = ?
            ORDER BY completed_at DESC
            LIMIT 1
        """, (resource_id, action_type))

        row = cur.fetchone()
        return None if not row else row["status"]
