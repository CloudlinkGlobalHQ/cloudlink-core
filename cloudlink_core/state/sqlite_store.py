from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cloudlink_core.state.crypto import decrypt_credential, encrypt_credential, mask_credential


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def action_key_for(resource_id: str, action_type: str, proposed_change: Optional[Dict[str, Any]]) -> str:
    raw = f"{resource_id}|{action_type}|{_stable_json(proposed_change or {})}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# Statuses that count as "active" — a new action should not be created while one exists
ACTIVE_STATUSES = ("PENDING", "IN_PROGRESS", "RETRY", "AWAITING_APPROVAL")


class SQLiteStateStore:
    """
    SQLite-backed Cloudlink state store.

    Multi-tenant: every resource, action, result, and run is scoped to a tenant_id.
    Existing single-tenant data is migrated to tenant_id='default'.

    Tables:
      tenants            — one row per client
      api_keys           — hashed API keys → tenant_id
      cloud_credentials  — encrypted per-tenant cloud credentials
      approval_policies  — per-tenant per-action-type approval rules
      resources          — latest resource state per tenant
      actions            — action lifecycle per tenant
      execution_results  — append-only execution history per tenant
      runs               — one row per run_loop execution per tenant
    """

    DEFAULT_TENANT = "default"

    def __init__(self, db_path: str = "cloudlink.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30,
        )
        self.conn.row_factory = sqlite3.Row
        # WAL mode: allows concurrent readers + one writer without locking
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.commit()
        self._create_tables()
        self._migrate_tables()
        self._seed_default_tenant()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id  TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_hash   TEXT PRIMARY KEY,
            tenant_id  TEXT NOT NULL,
            label      TEXT,
            created_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_credentials (
            credential_id     TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            cloud             TEXT NOT NULL,
            label             TEXT,
            credential_type   TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at        TEXT NOT NULL,
            last_verified_at  TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_credentials_tenant
        ON cloud_credentials(tenant_id)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS approval_policies (
            tenant_id                  TEXT NOT NULL,
            action_type                TEXT NOT NULL,
            require_approval           INTEGER NOT NULL DEFAULT 1,
            auto_approve_min_confidence REAL,
            PRIMARY KEY (tenant_id, action_type)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            resource_id TEXT NOT NULL,
            tenant_id   TEXT NOT NULL DEFAULT 'default',
            payload     TEXT,
            PRIMARY KEY (resource_id, tenant_id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS execution_results (
            result_id    TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL DEFAULT 'default',
            action_id    TEXT NOT NULL,
            status       TEXT,
            completed_at TEXT,
            resource_id  TEXT,
            action_type  TEXT,
            payload      TEXT
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
        # idx_exec_tenant created in _migrate_tables() after tenant_id column is ensured

        cur.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            action_id      TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL DEFAULT 'default',
            action_key     TEXT UNIQUE NOT NULL,
            agent          TEXT,
            action_type    TEXT NOT NULL,
            resource_id    TEXT NOT NULL,
            resource_type  TEXT,
            proposed_change TEXT,
            status         TEXT NOT NULL,
            attempt_count  INTEGER NOT NULL DEFAULT 0,
            next_retry_at  TEXT,
            last_error     TEXT,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL
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
        # idx_actions_tenant_status created in _migrate_tables() after tenant_id column is ensured

        cur.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id         TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL DEFAULT 'default',
            started_at     TEXT NOT NULL,
            finished_at    TEXT,
            proposed_count INTEGER DEFAULT 0,
            claimed_count  INTEGER DEFAULT 0,
            success_count  INTEGER DEFAULT 0,
            failed_count   INTEGER DEFAULT 0,
            retry_count    INTEGER DEFAULT 0,
            status         TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_runs_started_at
        ON runs(started_at)
        """)
        # idx_runs_tenant created in _migrate_tables() after tenant_id column is ensured

        cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id          TEXT PRIMARY KEY,
            tenant_id        TEXT NOT NULL,
            credential_id    TEXT,
            credential_label TEXT,
            regions          TEXT,
            started_at       TEXT NOT NULL,
            finished_at      TEXT,
            status           TEXT NOT NULL DEFAULT 'running',
            events_found     INTEGER DEFAULT 0,
            events_ingested  INTEGER DEFAULT 0,
            actions_queued   INTEGER DEFAULT 0,
            error            TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_tenant
        ON scan_history(tenant_id, started_at)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id    TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            url           TEXT NOT NULL,
            secret        TEXT,
            events        TEXT NOT NULL DEFAULT '["action.created","action.completed","scan.finished"]',
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL,
            last_fired_at TEXT,
            last_status   TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhooks_tenant
        ON webhooks(tenant_id)
        """)

        self.conn.commit()

    def _migrate_tables(self) -> None:
        """
        Add tenant_id to pre-existing single-tenant tables.
        Runs safely on both fresh and existing databases.
        """
        cur = self.conn.cursor()

        migrations = {
            "resources":         "tenant_id TEXT NOT NULL DEFAULT 'default'",
            "actions":           "tenant_id TEXT NOT NULL DEFAULT 'default'",
            "execution_results": "tenant_id TEXT NOT NULL DEFAULT 'default'",
            "runs":              "tenant_id TEXT NOT NULL DEFAULT 'default'",
        }

        for table, col_def in migrations.items():
            cur.execute(f"PRAGMA table_info({table})")
            existing_cols = {row["name"] for row in cur.fetchall()}
            if "tenant_id" not in existing_cols:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")

        # Create tenant_id indexes now that the column is guaranteed to exist
        cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_tenant ON execution_results(tenant_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions(tenant_id, status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id)")

        self.conn.commit()

    def _seed_default_tenant(self) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR IGNORE INTO tenants (tenant_id, name, status, created_at)
            VALUES (?, ?, ?, ?)
        """, (self.DEFAULT_TENANT, "Default Tenant", "active", _now_iso()))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    def create_tenant(self, name: str) -> str:
        tenant_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO tenants (tenant_id, name, status, created_at)
            VALUES (?, ?, ?, ?)
        """, (tenant_id, name, "active", _now_iso()))
        self.conn.commit()
        return tenant_id

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_tenants(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM tenants ORDER BY created_at")
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    def add_api_key(self, tenant_id: str, raw_key: str, label: Optional[str] = None) -> str:
        """Store a hashed API key for a tenant. Returns the key_hash."""
        key_hash = _hash_api_key(raw_key)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO api_keys (key_hash, tenant_id, label, created_at)
            VALUES (?, ?, ?, ?)
        """, (key_hash, tenant_id, label, _now_iso()))
        self.conn.commit()
        return key_hash

    def get_tenant_id_for_api_key(self, raw_key: str) -> Optional[str]:
        """Look up a tenant_id by raw API key. Returns None if not found."""
        key_hash = _hash_api_key(raw_key)
        cur = self.conn.cursor()
        cur.execute("""
            SELECT tenant_id FROM api_keys WHERE key_hash = ?
        """, (key_hash,))
        row = cur.fetchone()
        return row["tenant_id"] if row else None

    # ------------------------------------------------------------------
    # Cloud Credentials
    # ------------------------------------------------------------------

    def add_credential(
        self,
        tenant_id: str,
        cloud: str,
        credential_type: str,
        payload: str,
        label: Optional[str] = None,
    ) -> str:
        """Encrypt and store a cloud credential. Returns credential_id."""
        credential_id = str(uuid.uuid4())
        encrypted = encrypt_credential(payload)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cloud_credentials
            (credential_id, tenant_id, cloud, label, credential_type, encrypted_payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (credential_id, tenant_id, cloud, label, credential_type, encrypted, _now_iso()))
        self.conn.commit()
        return credential_id

    def list_credentials(self, tenant_id: str) -> List[Dict[str, Any]]:
        """List credentials for a tenant. Payload is masked — never returns plaintext."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT credential_id, tenant_id, cloud, label, credential_type, created_at, last_verified_at
            FROM cloud_credentials
            WHERE tenant_id = ?
            ORDER BY created_at
        """, (tenant_id,))
        return [dict(r) for r in cur.fetchall()]

    def get_decrypted_credential(self, tenant_id: str, credential_id: str) -> Optional[str]:
        """Return the decrypted payload for a credential. Only called by executors."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT encrypted_payload FROM cloud_credentials
            WHERE credential_id = ? AND tenant_id = ?
        """, (credential_id, tenant_id))
        row = cur.fetchone()
        if not row:
            return None
        return decrypt_credential(row["encrypted_payload"])

    def delete_credential(self, tenant_id: str, credential_id: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("""
            DELETE FROM cloud_credentials
            WHERE credential_id = ? AND tenant_id = ?
        """, (credential_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def mark_credential_verified(self, tenant_id: str, credential_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE cloud_credentials SET last_verified_at = ?
            WHERE credential_id = ? AND tenant_id = ?
        """, (_now_iso(), credential_id, tenant_id))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Approval Policies
    # ------------------------------------------------------------------

    def get_approval_policy(self, tenant_id: str, action_type: str) -> Dict[str, Any]:
        """
        Return the approval policy for a tenant+action_type.
        Defaults to require_approval=True if no policy is set.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT require_approval, auto_approve_min_confidence
            FROM approval_policies
            WHERE tenant_id = ? AND action_type = ?
        """, (tenant_id, action_type))
        row = cur.fetchone()
        if row:
            return {
                "require_approval": bool(row["require_approval"]),
                "auto_approve_min_confidence": row["auto_approve_min_confidence"],
            }
        # Default: require approval for all actions
        return {"require_approval": True, "auto_approve_min_confidence": None}

    def set_approval_policy(
        self,
        tenant_id: str,
        action_type: str,
        require_approval: bool,
        auto_approve_min_confidence: Optional[float] = None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO approval_policies
                (tenant_id, action_type, require_approval, auto_approve_min_confidence)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(tenant_id, action_type) DO UPDATE SET
                require_approval = excluded.require_approval,
                auto_approve_min_confidence = excluded.auto_approve_min_confidence
        """, (tenant_id, action_type, int(require_approval), auto_approve_min_confidence))
        self.conn.commit()

    def list_approval_policies(self, tenant_id: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT action_type, require_approval, auto_approve_min_confidence
            FROM approval_policies WHERE tenant_id = ?
            ORDER BY action_type
        """, (tenant_id,))
        return [
            {
                "action_type": r["action_type"],
                "require_approval": bool(r["require_approval"]),
                "auto_approve_min_confidence": r["auto_approve_min_confidence"],
            }
            for r in cur.fetchall()
        ]

    # ------------------------------------------------------------------
    # Resource State
    # ------------------------------------------------------------------

    def ingest_event(self, event: Dict[str, Any], tenant_id: str = DEFAULT_TENANT) -> None:
        resource_id = event.get("resource_id")
        if not resource_id:
            raise ValueError("event must contain resource_id")
        payload = json.dumps(event)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO resources (resource_id, tenant_id, payload)
            VALUES (?, ?, ?)
        """, (resource_id, tenant_id, payload))
        self.conn.commit()

    def get_resource(self, resource_id: str, tenant_id: str = DEFAULT_TENANT) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT payload FROM resources WHERE resource_id = ? AND tenant_id = ?",
            (resource_id, tenant_id),
        )
        row = cur.fetchone()
        return json.loads(row["payload"]) if row else None

    def list_resources(self, tenant_id: str = DEFAULT_TENANT) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT payload FROM resources WHERE tenant_id = ?", (tenant_id,))
        return [json.loads(r["payload"]) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # Execution Results (append-only)
    # ------------------------------------------------------------------

    def ingest_execution_result(self, result: Dict[str, Any], tenant_id: str = DEFAULT_TENANT) -> None:
        action_id = result.get("action_id")
        if not action_id:
            raise ValueError("execution result must contain action_id")
        result_id = result.get("result_id") or str(uuid.uuid4())
        payload = json.dumps(result)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO execution_results
            (result_id, tenant_id, action_id, status, completed_at, resource_id, action_type, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result_id, tenant_id, action_id,
            result.get("status"), result.get("completed_at"),
            result.get("resource_id"), result.get("action_type"),
            payload,
        ))
        self.conn.commit()

    def list_execution_results(self, tenant_id: str = DEFAULT_TENANT) -> Dict[str, Dict[str, Any]]:
        """Return latest result per action_id, scoped to tenant."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT er.action_id, er.payload
            FROM execution_results er
            JOIN (
                SELECT action_id, MAX(completed_at) AS max_completed_at
                FROM execution_results
                WHERE tenant_id = ?
                GROUP BY action_id
            ) latest ON er.action_id = latest.action_id
                     AND er.completed_at = latest.max_completed_at
            WHERE er.tenant_id = ?
        """, (tenant_id, tenant_id))
        return {r["action_id"]: json.loads(r["payload"]) for r in cur.fetchall()}

    def list_execution_results_for_action(self, action_id: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT payload FROM execution_results
            WHERE action_id = ?
            ORDER BY completed_at ASC
        """, (action_id,))
        return [json.loads(r["payload"]) for r in cur.fetchall()]

    def last_success_completed_at(self, resource_id: str, action_type: str, tenant_id: str = DEFAULT_TENANT) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT completed_at FROM execution_results
            WHERE resource_id = ? AND action_type = ? AND status = 'SUCCESS' AND tenant_id = ?
            ORDER BY completed_at DESC LIMIT 1
        """, (resource_id, action_type, tenant_id))
        row = cur.fetchone()
        return None if not row else row["completed_at"]

    # ------------------------------------------------------------------
    # Actions Lifecycle
    # ------------------------------------------------------------------

    def _resolve_initial_status(self, tenant_id: str, action_type: str, confidence: Optional[float]) -> str:
        """
        Check the tenant's approval policy and determine the correct initial status.
        Returns 'AWAITING_APPROVAL' or 'PENDING'.
        """
        policy = self.get_approval_policy(tenant_id, action_type)
        if not policy["require_approval"]:
            return "PENDING"
        min_conf = policy["auto_approve_min_confidence"]
        if min_conf is not None and confidence is not None and confidence >= min_conf:
            return "PENDING"
        return "AWAITING_APPROVAL"

    def create_action_if_new(self, action: Dict[str, Any], tenant_id: str = DEFAULT_TENANT) -> bool:
        """
        Insert action if its action_key is not already in the database.
        Applies approval policy to determine initial status (overrides action['status']).
        Returns True if inserted, False if duplicate.
        """
        required = ["action_id", "action_key", "action_type", "resource_id", "created_at", "updated_at"]
        for k in required:
            if not action.get(k):
                raise ValueError(f"action missing required field: {k}")

        initial_status = self._resolve_initial_status(
            tenant_id,
            action["action_type"],
            action.get("confidence"),
        )

        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO actions (
                    action_id, tenant_id, action_key, agent, action_type, resource_id,
                    resource_type, proposed_change, status, attempt_count,
                    next_retry_at, last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action["action_id"],
                tenant_id,
                action["action_key"],
                action.get("agent"),
                action["action_type"],
                action["resource_id"],
                action.get("resource_type"),
                _stable_json(action.get("proposed_change") or {}),
                initial_status,
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

    def claim_actions(self, limit: int, tenant_id: str = DEFAULT_TENANT) -> List[Dict[str, Any]]:
        """Atomically claim PENDING/RETRY actions for a tenant, setting them IN_PROGRESS."""
        now = _now_iso()
        cur = self.conn.cursor()
        cur.execute("""
            SELECT action_id FROM actions
            WHERE tenant_id = ?
              AND status IN ('PENDING', 'RETRY')
              AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?
        """, (tenant_id, now, int(limit)))

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
        return [self._row_to_action(r) for r in cur.fetchall()]

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

    def approve_action(self, action_id: str, tenant_id: str) -> bool:
        """Move an AWAITING_APPROVAL action to PENDING so it can be claimed."""
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE actions SET status='PENDING', updated_at=?
            WHERE action_id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'
        """, (_now_iso(), action_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def reject_action(self, action_id: str, tenant_id: str) -> bool:
        """Move an AWAITING_APPROVAL action to FAILED."""
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE actions SET status='FAILED', updated_at=?
            WHERE action_id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'
        """, (_now_iso(), action_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def force_retry_action(self, action_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE actions SET status='RETRY', next_retry_at=NULL, updated_at=?
            WHERE action_id = ?
        """, (_now_iso(), action_id))
        self.conn.commit()

    def has_active_action(self, resource_id: str, action_type: str, tenant_id: str = DEFAULT_TENANT) -> bool:
        """Return True if an active action exists for this tenant+resource+type."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT COUNT(*) AS n FROM actions
            WHERE resource_id = ? AND action_type = ? AND tenant_id = ?
              AND status IN ('PENDING', 'IN_PROGRESS', 'RETRY', 'AWAITING_APPROVAL')
        """, (resource_id, action_type, tenant_id))
        return int(cur.fetchone()["n"]) > 0

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def create_run(self, tenant_id: str = DEFAULT_TENANT) -> str:
        run_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO runs (run_id, tenant_id, started_at, status)
            VALUES (?, ?, ?, ?)
        """, (run_id, tenant_id, _now_iso(), "RUNNING"))
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
            SET finished_at=?, proposed_count=?, claimed_count=?,
                success_count=?, failed_count=?, retry_count=?, status='FINISHED'
            WHERE run_id=?
        """, (
            _now_iso(), int(proposed_count), int(claimed_count),
            int(success_count), int(failed_count), int(retry_count), run_id,
        ))
        self.conn.commit()

    def list_runs(self, limit: int = 50, tenant_id: str = DEFAULT_TENANT) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM runs WHERE tenant_id = ?
            ORDER BY started_at DESC LIMIT ?
        """, (tenant_id, int(limit)))
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # Read Helpers (API)
    # ------------------------------------------------------------------

    def _row_to_action(self, r: sqlite3.Row) -> Dict[str, Any]:
        return {
            "action_id":      r["action_id"],
            "tenant_id":      r["tenant_id"],
            "action_key":     r["action_key"],
            "agent":          r["agent"],
            "action_type":    r["action_type"],
            "resource_id":    r["resource_id"],
            "resource_type":  r["resource_type"],
            "proposed_change": json.loads(r["proposed_change"] or "{}"),
            "status":         r["status"],
            "attempt_count":  int(r["attempt_count"] or 0),
            "next_retry_at":  r["next_retry_at"],
            "last_error":     r["last_error"],
            "created_at":     r["created_at"],
            "updated_at":     r["updated_at"],
        }

    def get_action(self, action_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        if tenant_id:
            cur.execute("SELECT * FROM actions WHERE action_id = ? AND tenant_id = ?", (action_id, tenant_id))
        else:
            cur.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
        r = cur.fetchone()
        return self._row_to_action(r) if r else None

    def list_actions(
        self,
        status: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
        tenant_id: str = DEFAULT_TENANT,
    ) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if status:
            cur.execute("""
                SELECT action_id FROM actions
                WHERE tenant_id = ? AND status = ?
                ORDER BY updated_at DESC LIMIT ? OFFSET ?
            """, (tenant_id, status, int(limit), int(offset)))
        else:
            cur.execute("""
                SELECT action_id FROM actions
                WHERE tenant_id = ?
                ORDER BY updated_at DESC LIMIT ? OFFSET ?
            """, (tenant_id, int(limit), int(offset)))

        out: List[Dict[str, Any]] = []
        for r in cur.fetchall():
            a = self.get_action(r["action_id"])
            if a:
                out.append(a)
        return out

    def count_actions_by_status(self, tenant_id: str = DEFAULT_TENANT) -> Dict[str, int]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT status, COUNT(*) AS n FROM actions
            WHERE tenant_id = ?
            GROUP BY status
        """, (tenant_id,))
        return {r["status"]: int(r["n"]) for r in cur.fetchall()}

    # ------------------------------------------------------------------
    # Scan History
    # ------------------------------------------------------------------

    def create_scan(
        self,
        tenant_id: str,
        credential_id: Optional[str] = None,
        credential_label: Optional[str] = None,
        regions: Optional[List[str]] = None,
    ) -> str:
        scan_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO scan_history
            (scan_id, tenant_id, credential_id, credential_label, regions, started_at, status)
            VALUES (?, ?, ?, ?, ?, ?, 'running')
        """, (
            scan_id, tenant_id, credential_id, credential_label,
            json.dumps(regions or []), _now_iso(),
        ))
        self.conn.commit()
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
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE scan_history
            SET finished_at=?, status=?, events_found=?, events_ingested=?, actions_queued=?, error=?
            WHERE scan_id=?
        """, (_now_iso(), status, events_found, events_ingested, actions_queued, error, scan_id))
        self.conn.commit()

    def list_scans(self, tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM scan_history WHERE tenant_id = ?
            ORDER BY started_at DESC LIMIT ?
        """, (tenant_id, int(limit)))
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["regions"] = json.loads(d["regions"] or "[]")
            except Exception:
                d["regions"] = []
            rows.append(d)
        return rows

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    def add_webhook(
        self,
        tenant_id: str,
        url: str,
        secret: Optional[str] = None,
        events: Optional[List[str]] = None,
    ) -> str:
        webhook_id = str(uuid.uuid4())
        default_events = ["action.created", "action.completed", "scan.finished"]
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO webhooks (webhook_id, tenant_id, url, secret, events, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        """, (
            webhook_id, tenant_id, url, secret,
            json.dumps(events or default_events), _now_iso(),
        ))
        self.conn.commit()
        return webhook_id

    def list_webhooks(self, tenant_id: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM webhooks WHERE tenant_id = ? ORDER BY created_at
        """, (tenant_id,))
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
        cur = self.conn.cursor()
        cur.execute("""
            DELETE FROM webhooks WHERE webhook_id = ? AND tenant_id = ?
        """, (webhook_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def update_webhook_status(self, webhook_id: str, status: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE webhooks SET last_fired_at=?, last_status=? WHERE webhook_id=?
        """, (_now_iso(), status, webhook_id))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Notification helper (fire-and-forget HTTP POST to webhooks)
    # ------------------------------------------------------------------

    def fire_webhooks(self, tenant_id: str, event_type: str, payload: Dict[str, Any]) -> None:
        """Fire matching webhooks for a tenant event. Errors are silently swallowed."""
        try:
            import threading
            import urllib.request

            webhooks = self.list_webhooks(tenant_id)
            for wh in webhooks:
                if not wh.get("enabled"):
                    continue
                if event_type not in wh.get("events", []):
                    continue

                body = json.dumps({"event": event_type, "payload": payload}).encode()
                headers = {"Content-Type": "application/json"}
                if wh.get("secret"):
                    import hashlib
                    import hmac
                    sig = hmac.new(wh["secret"].encode(), body, hashlib.sha256).hexdigest()
                    headers["X-Cloudlink-Signature"] = f"sha256={sig}"

                def _send(url=wh["url"], wid=wh["webhook_id"], b=body, h=headers):
                    try:
                        req = urllib.request.Request(url, data=b, headers=h, method="POST")
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            self.update_webhook_status(wid, str(resp.status))
                    except Exception as exc:
                        self.update_webhook_status(wid, f"error: {exc}")

                threading.Thread(target=_send, daemon=True).start()
        except Exception:
            pass
