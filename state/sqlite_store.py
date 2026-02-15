import sqlite3
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class SQLiteStateStore:
    """
    SQLite-backed implementation of the state store.

    This version:
    - opens DB connection
    - creates tables automatically
    - supports execution result ingestion
    - supports resource storage
    """

    def __init__(self, db_path: str = "cloudlink.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    # -------------------------
    # Table creation
    # -------------------------
    def _create_tables(self):
        cur = self.conn.cursor()

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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            resource_id TEXT PRIMARY KEY,
            payload TEXT
        )
        """)

        self.conn.commit()

    # -------------------------
    # Event / Resource state
    # -------------------------
    def ingest_event(self, event: Dict[str, Any]) -> None:
        resource_id = event.get("resource_id")
        if not resource_id:
            return

        payload = json.dumps(event)

        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO resources (resource_id, payload)
            VALUES (?, ?)
        """, (resource_id, payload))
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
        rows = cur.fetchall()
        return [json.loads(r["payload"]) for r in rows]

    # -------------------------
    # Execution Results
    # -------------------------
    def ingest_execution_result(self, result: Dict[str, Any]) -> None:
        payload = json.dumps(result)

        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO execution_results
            (action_id, status, completed_at, resource_id, action_type, payload)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            result.get("action_id"),
            result.get("status"),
            result.get("completed_at"),
            result.get("resource_id"),
            result.get("action_type"),
            payload
        ))
        self.conn.commit()

    def list_execution_results(self) -> Dict[str, Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT action_id, payload FROM execution_results")
        rows = cur.fetchall()

        out = {}
        for r in rows:
            out[r["action_id"]] = json.loads(r["payload"])
        return out
