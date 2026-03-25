from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
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
        self.conn.execute("PRAGMA busy_timeout=10000")
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
            reason         TEXT,
            confidence     REAL,
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

        # ── Cost regression pipeline ───────────────────────────────────────

        cur.execute("""
        CREATE TABLE IF NOT EXISTS cost_snapshots (
            snapshot_id   TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            credential_id TEXT,
            service       TEXT NOT NULL,
            hour          TEXT NOT NULL,
            cost_usd      REAL NOT NULL,
            recorded_at   TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cost_snapshot_uniq
        ON cost_snapshots(tenant_id, service, hour)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_cost_snapshot_tenant_svc
        ON cost_snapshots(tenant_id, service, hour)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS deploy_events (
            deploy_id    TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            service      TEXT NOT NULL,
            version      TEXT,
            environment  TEXT NOT NULL DEFAULT 'production',
            deployed_at  TEXT NOT NULL,
            source       TEXT,
            metadata     TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_deploy_tenant_service
        ON deploy_events(tenant_id, service, deployed_at)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS cost_regressions (
            regression_id  TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            deploy_id      TEXT NOT NULL,
            service        TEXT NOT NULL,
            baseline_cost  REAL NOT NULL,
            post_cost      REAL NOT NULL,
            change_pct     REAL NOT NULL,
            monthly_impact REAL NOT NULL,
            detected_at    TEXT NOT NULL,
            status         TEXT NOT NULL DEFAULT 'open',
            confidence     TEXT NOT NULL DEFAULT 'high'
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_regression_tenant
        ON cost_regressions(tenant_id, detected_at)
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_regression_deploy_svc
        ON cost_regressions(deploy_id, service)
        """)

        # ── Subscriptions (Stripe billing) ──────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            clerk_user_id       TEXT NOT NULL,
            tenant_id           TEXT NOT NULL DEFAULT 'default',
            stripe_customer_id  TEXT,
            stripe_subscription_id TEXT,
            plan                TEXT NOT NULL DEFAULT 'free',
            status              TEXT NOT NULL DEFAULT 'active',
            current_period_end  TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_clerk_user
        ON subscriptions(clerk_user_id)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_sub_stripe_customer
        ON subscriptions(stripe_customer_id)
        """)

        # ── Budget guardrails ────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS budgets (
            budget_id         TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            name              TEXT NOT NULL,
            scope             TEXT NOT NULL DEFAULT 'total',
            service           TEXT,
            monthly_limit_usd REAL NOT NULL,
            alert_thresholds  TEXT NOT NULL DEFAULT '[50,80,100]',
            action_on_breach  TEXT NOT NULL DEFAULT 'alert',
            enabled           INTEGER NOT NULL DEFAULT 1,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_budgets_tenant
        ON budgets(tenant_id)
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS budget_alerts (
            alert_id          TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            budget_id         TEXT NOT NULL,
            threshold_pct     INTEGER NOT NULL,
            current_spend_usd REAL NOT NULL,
            budget_limit_usd  REAL NOT NULL,
            triggered_at      TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_budget_alerts_tenant
        ON budget_alerts(tenant_id, budget_id, triggered_at)
        """)

        # ── AutoStop rules ───────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS autostop_rules (
            rule_id           TEXT PRIMARY KEY,
            tenant_id         TEXT NOT NULL,
            name              TEXT NOT NULL,
            enabled           INTEGER NOT NULL DEFAULT 1,
            environment_tag   TEXT NOT NULL DEFAULT '*',
            resource_types    TEXT NOT NULL DEFAULT '["ec2_instance"]',
            idle_threshold_pct REAL NOT NULL DEFAULT 5.0,
            idle_lookback_hours INTEGER NOT NULL DEFAULT 24,
            schedule_stop     TEXT,
            schedule_start    TEXT,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_autostop_rules_tenant
        ON autostop_rules(tenant_id)
        """)

        # ── AutoStop events ──────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS autostop_events (
            event_id            TEXT PRIMARY KEY,
            tenant_id           TEXT NOT NULL,
            rule_id             TEXT,
            resource_id         TEXT NOT NULL,
            resource_type       TEXT NOT NULL,
            action              TEXT NOT NULL,
            reason              TEXT,
            savings_usd_est     REAL,
            region              TEXT,
            created_at          TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_autostop_events_tenant
        ON autostop_events(tenant_id, created_at)
        """)

        # ── Team members ────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS team_members (
            member_id       TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            email           TEXT NOT NULL,
            name            TEXT,
            role            TEXT NOT NULL DEFAULT 'viewer',
            invited_by      TEXT,
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_team_members_tenant
        ON team_members(tenant_id)
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_team_members_tenant_email
        ON team_members(tenant_id, email)
        """)

        # ── Virtual Tags ─────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS virtual_tags (
            tag_id      TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            name        TEXT NOT NULL,
            color       TEXT NOT NULL DEFAULT '#6366f1',
            rules       TEXT NOT NULL DEFAULT '[]',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_virtual_tags_tenant
        ON virtual_tags(tenant_id)
        """)

        # ── Kubernetes cost records ───────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS k8s_cost_records (
            id          TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            cluster     TEXT NOT NULL,
            namespace   TEXT NOT NULL,
            pod         TEXT,
            container   TEXT,
            node        TEXT,
            cpu_cores   REAL DEFAULT 0,
            mem_gib     REAL DEFAULT 0,
            cpu_cost_usd  REAL DEFAULT 0,
            mem_cost_usd  REAL DEFAULT 0,
            total_cost_usd REAL DEFAULT 0,
            hour        TEXT NOT NULL,
            labels      TEXT DEFAULT '{}'
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_k8s_cost_tenant_hour
        ON k8s_cost_records(tenant_id, hour)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_k8s_cost_namespace
        ON k8s_cost_records(tenant_id, cluster, namespace)
        """)

        self.conn.commit()

    def _migrate_tables(self) -> None:
        """
        Add tenant_id to pre-existing single-tenant tables.
        Runs safely on both fresh and existing databases.
        """
        cur = self.conn.cursor()

        migrations = {
            "resources":         [("tenant_id", "TEXT NOT NULL DEFAULT 'default'")],
            "actions":           [("tenant_id", "TEXT NOT NULL DEFAULT 'default'"),
                                  ("reason",    "TEXT"),
                                  ("confidence","REAL")],
            "execution_results": [("tenant_id", "TEXT NOT NULL DEFAULT 'default'")],
            "runs":              [("tenant_id", "TEXT NOT NULL DEFAULT 'default'")],
        }

        for table, col_defs in migrations.items():
            cur.execute(f"PRAGMA table_info({table})")
            existing_cols = {row["name"] for row in cur.fetchall()}
            for col_name, col_def in col_defs:
                if col_name not in existing_cols:
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")

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
                    next_retry_at, last_error, reason, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                action.get("reason"),
                action.get("confidence"),
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
        keys = r.keys() if hasattr(r, "keys") else []
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
            "reason":         r["reason"] if "reason" in keys else None,
            "confidence":     r["confidence"] if "confidence" in keys else None,
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

    # ------------------------------------------------------------------
    # Cost Snapshots
    # ------------------------------------------------------------------

    def record_cost_snapshot(
        self,
        tenant_id: str,
        service: str,
        hour: str,
        cost_usd: float,
        credential_id: Optional[str] = None,
    ) -> None:
        """Upsert a per-service hourly cost reading. Idempotent on (tenant, service, hour)."""
        snapshot_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cost_snapshots
                (snapshot_id, tenant_id, credential_id, service, hour, cost_usd, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, service, hour) DO UPDATE SET
                cost_usd    = excluded.cost_usd,
                recorded_at = excluded.recorded_at
        """, (snapshot_id, tenant_id, credential_id, service, hour, cost_usd, _now_iso()))
        self.conn.commit()

    def get_cost_baseline(
        self,
        tenant_id: str,
        service: str,
        before_hour: str,
        lookback_hours: int = 168,  # 7 days
    ) -> Optional[float]:
        """
        Return the average hourly cost for `service` over the `lookback_hours` window
        that ends at (but excludes) `before_hour`. Returns None if no data.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT AVG(cost_usd) AS avg_cost, COUNT(*) AS n
            FROM cost_snapshots
            WHERE tenant_id = ?
              AND service   = ?
              AND hour      < ?
            ORDER BY hour DESC
            LIMIT ?
        """, (tenant_id, service, before_hour, lookback_hours))
        row = cur.fetchone()
        if not row or row["n"] == 0:
            return None
        return row["avg_cost"]

    def get_post_deploy_cost(
        self,
        tenant_id: str,
        service: str,
        after_hour: str,
        window_hours: int = 3,
    ) -> Optional[float]:
        """
        Return the average hourly cost for `service` in the `window_hours` window
        starting at `after_hour`. Returns None if no data yet.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT AVG(cost_usd) AS avg_cost, COUNT(*) AS n
            FROM (
                SELECT cost_usd FROM cost_snapshots
                WHERE tenant_id = ?
                  AND service   = ?
                  AND hour      >= ?
                ORDER BY hour ASC
                LIMIT ?
            )
        """, (tenant_id, service, after_hour, window_hours))
        row = cur.fetchone()
        if not row or row["n"] == 0:
            return None
        return row["avg_cost"]

    def list_cost_snapshots(
        self,
        tenant_id: str,
        service: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if service:
            cur.execute("""
                SELECT * FROM cost_snapshots
                WHERE tenant_id = ? AND service = ?
                ORDER BY hour DESC LIMIT ?
            """, (tenant_id, service, limit))
        else:
            cur.execute("""
                SELECT * FROM cost_snapshots
                WHERE tenant_id = ?
                ORDER BY hour DESC LIMIT ?
            """, (tenant_id, limit))
        return [dict(r) for r in cur.fetchall()]

    def list_tracked_services(self, tenant_id: str) -> List[str]:
        """Return distinct service names that have cost snapshots."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT DISTINCT service FROM cost_snapshots
            WHERE tenant_id = ?
            ORDER BY service
        """, (tenant_id,))
        return [r["service"] for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # Deploy Events
    # ------------------------------------------------------------------

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
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO deploy_events
                (deploy_id, tenant_id, service, version, environment, deployed_at, source, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            deploy_id, tenant_id, service, version, environment,
            deployed_at, source, json.dumps(metadata or {}),
        ))
        self.conn.commit()
        return deploy_id

    def get_deploy_event(self, deploy_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM deploy_events WHERE deploy_id = ? AND tenant_id = ?
        """, (deploy_id, tenant_id))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d.get("metadata") or "{}")
        return d

    def list_deploy_events(
        self,
        tenant_id: str,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if service:
            cur.execute("""
                SELECT * FROM deploy_events
                WHERE tenant_id = ? AND service = ?
                ORDER BY deployed_at DESC LIMIT ?
            """, (tenant_id, service, limit))
        else:
            cur.execute("""
                SELECT * FROM deploy_events
                WHERE tenant_id = ?
                ORDER BY deployed_at DESC LIMIT ?
            """, (tenant_id, limit))
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["metadata"] = json.loads(d.get("metadata") or "{}")
            rows.append(d)
        return rows

    def get_deploys_pending_analysis(
        self,
        tenant_id: str,
        min_hours_elapsed: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """
        Return deploy events that:
          1. Were deployed at least `min_hours_elapsed` hours ago
          2. Do not yet have a regression record (checked or clean)
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=min_hours_elapsed)
        cutoff_iso = cutoff.isoformat()
        cur = self.conn.cursor()
        cur.execute("""
            SELECT d.* FROM deploy_events d
            WHERE d.tenant_id = ?
              AND d.deployed_at <= ?
              AND NOT EXISTS (
                SELECT 1 FROM cost_regressions r
                WHERE r.deploy_id = d.deploy_id
                  AND r.service   = d.service
              )
            ORDER BY d.deployed_at ASC
        """, (tenant_id, cutoff_iso))
        rows = []
        for r in cur.fetchall():
            dd = dict(r)
            dd["metadata"] = json.loads(dd.get("metadata") or "{}")
            rows.append(dd)
        return rows

    # ------------------------------------------------------------------
    # Cost Regressions
    # ------------------------------------------------------------------

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
        cur = self.conn.cursor()
        try:
            cur.execute("""
                INSERT INTO cost_regressions
                    (regression_id, tenant_id, deploy_id, service,
                     baseline_cost, post_cost, change_pct, monthly_impact,
                     detected_at, status, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """, (
                regression_id, tenant_id, deploy_id, service,
                baseline_cost, post_cost, round(change_pct, 2),
                round(monthly_impact, 2), _now_iso(), confidence,
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            # duplicate (deploy_id, service) — already recorded
            return ""
        return regression_id

    def acknowledge_regression(self, regression_id: str, tenant_id: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE cost_regressions SET status = 'acknowledged'
            WHERE regression_id = ? AND tenant_id = ? AND status = 'open'
        """, (regression_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def resolve_regression(self, regression_id: str, tenant_id: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE cost_regressions SET status = 'resolved'
            WHERE regression_id = ? AND tenant_id = ?
        """, (regression_id, tenant_id))
        self.conn.commit()
        return cur.rowcount > 0

    def list_regressions(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if status:
            cur.execute("""
                SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
                FROM cost_regressions r
                LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
                WHERE r.tenant_id = ? AND r.status = ?
                ORDER BY r.detected_at DESC LIMIT ?
            """, (tenant_id, status, limit))
        else:
            cur.execute("""
                SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
                FROM cost_regressions r
                LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
                WHERE r.tenant_id = ?
                ORDER BY r.detected_at DESC LIMIT ?
            """, (tenant_id, limit))
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["deploy_metadata"] = json.loads(d.get("deploy_metadata") or "{}")
            rows.append(d)
        return rows

    def get_regression(self, regression_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT r.*, d.version, d.environment, d.deployed_at, d.source, d.metadata AS deploy_metadata
            FROM cost_regressions r
            LEFT JOIN deploy_events d ON r.deploy_id = d.deploy_id
            WHERE r.regression_id = ? AND r.tenant_id = ?
        """, (regression_id, tenant_id))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["deploy_metadata"] = json.loads(d.get("deploy_metadata") or "{}")
        return d

    # ------------------------------------------------------------------
    # AutoStop Rules
    # ------------------------------------------------------------------

    def create_autostop_rule(
        self,
        tenant_id: str,
        name: str,
        environment_tag: str = "*",
        resource_types: Optional[List[str]] = None,
        idle_threshold_pct: float = 5.0,
        idle_lookback_hours: int = 24,
        schedule_stop: Optional[str] = None,
        schedule_start: Optional[str] = None,
        enabled: bool = True,
    ) -> str:
        rule_id = str(uuid.uuid4())
        now = _now_iso()
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO autostop_rules
                (rule_id, tenant_id, name, enabled, environment_tag, resource_types,
                 idle_threshold_pct, idle_lookback_hours, schedule_stop, schedule_start,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_id, tenant_id, name, int(enabled), environment_tag,
            json.dumps(resource_types or ["ec2_instance"]),
            idle_threshold_pct, idle_lookback_hours,
            schedule_stop, schedule_start, now, now,
        ))
        self.conn.commit()
        return rule_id

    def list_autostop_rules(self, tenant_id: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM autostop_rules WHERE tenant_id = ? ORDER BY created_at DESC
        """, (tenant_id,))
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["resource_types"] = json.loads(d.get("resource_types") or '["ec2_instance"]')
            d["enabled"] = bool(d["enabled"])
            rows.append(d)
        return rows

    def get_autostop_rule(self, rule_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT * FROM autostop_rules WHERE rule_id = ? AND tenant_id = ?
        """, (rule_id, tenant_id))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["resource_types"] = json.loads(d.get("resource_types") or '["ec2_instance"]')
        d["enabled"] = bool(d["enabled"])
        return d

    def update_autostop_rule(self, rule_id: str, tenant_id: str, updates: Dict[str, Any]) -> bool:
        allowed = {
            "name", "enabled", "environment_tag", "resource_types",
            "idle_threshold_pct", "idle_lookback_hours", "schedule_stop", "schedule_start",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "resource_types" in fields:
            fields["resource_types"] = json.dumps(fields["resource_types"])
        if "enabled" in fields:
            fields["enabled"] = int(bool(fields["enabled"]))
        fields["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [rule_id, tenant_id]
        cur = self.conn.cursor()
        cur.execute(
            f"UPDATE autostop_rules SET {set_clause} WHERE rule_id = ? AND tenant_id = ?",
            vals,
        )
        self.conn.commit()
        return cur.rowcount > 0

    def delete_autostop_rule(self, rule_id: str, tenant_id: str) -> bool:
        cur = self.conn.cursor()
        cur.execute(
            "DELETE FROM autostop_rules WHERE rule_id = ? AND tenant_id = ?",
            (rule_id, tenant_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # AutoStop Events
    # ------------------------------------------------------------------

    def log_autostop_event(
        self,
        tenant_id: str,
        resource_id: str,
        resource_type: str,
        action: str,
        rule_id: Optional[str] = None,
        reason: Optional[str] = None,
        savings_usd_est: Optional[float] = None,
        region: Optional[str] = None,
    ) -> str:
        event_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO autostop_events
                (event_id, tenant_id, rule_id, resource_id, resource_type,
                 action, reason, savings_usd_est, region, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id, tenant_id, rule_id, resource_id, resource_type,
            action, reason, savings_usd_est, region, _now_iso(),
        ))
        self.conn.commit()
        return event_id

    def list_autostop_events(
        self,
        tenant_id: str,
        limit: int = 100,
        resource_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        if resource_id:
            cur.execute("""
                SELECT * FROM autostop_events
                WHERE tenant_id = ? AND resource_id = ?
                ORDER BY created_at DESC LIMIT ?
            """, (tenant_id, resource_id, limit))
        else:
            cur.execute("""
                SELECT * FROM autostop_events
                WHERE tenant_id = ?
                ORDER BY created_at DESC LIMIT ?
            """, (tenant_id, limit))
        return [dict(r) for r in cur.fetchall()]

    def get_autostop_savings(self, tenant_id: str) -> Dict[str, Any]:
        """Return estimated total savings and stopped resource count."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE action = 'stopped') AS total_stopped,
                COUNT(*) FILTER (WHERE action = 'started') AS total_started,
                COALESCE(SUM(savings_usd_est) FILTER (WHERE action = 'stopped'), 0) AS total_savings_usd
            FROM autostop_events WHERE tenant_id = ?
        """, (tenant_id,))
        row = cur.fetchone()
        return dict(row) if row else {"total_stopped": 0, "total_started": 0, "total_savings_usd": 0.0}

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

    # ------------------------------------------------------------------
    # Subscriptions (Stripe billing)
    # ------------------------------------------------------------------

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
        cur = self.conn.cursor()
        existing = cur.execute(
            "SELECT id FROM subscriptions WHERE clerk_user_id = ?",
            (clerk_user_id,),
        ).fetchone()

        if existing:
            cur.execute(
                """UPDATE subscriptions
                   SET stripe_customer_id = COALESCE(?, stripe_customer_id),
                       stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                       plan = ?,
                       status = ?,
                       current_period_end = COALESCE(?, current_period_end),
                       tenant_id = ?,
                       updated_at = ?
                 WHERE clerk_user_id = ?""",
                (stripe_customer_id, stripe_subscription_id, plan, status,
                 current_period_end, tenant_id, now, clerk_user_id),
            )
        else:
            cur.execute(
                """INSERT INTO subscriptions
                   (clerk_user_id, tenant_id, stripe_customer_id, stripe_subscription_id,
                    plan, status, current_period_end, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (clerk_user_id, tenant_id, stripe_customer_id, stripe_subscription_id,
                 plan, status, current_period_end, now, now),
            )
        self.conn.commit()
        return self.get_subscription(clerk_user_id)  # type: ignore

    def get_subscription(self, clerk_user_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM subscriptions WHERE clerk_user_id = ?",
            (clerk_user_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_subscription_by_customer(self, stripe_customer_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM subscriptions WHERE stripe_customer_id = ?",
            (stripe_customer_id,),
        ).fetchone()
        return dict(row) if row else None

    def cancel_subscription(self, clerk_user_id: str) -> None:
        self.conn.execute(
            "UPDATE subscriptions SET status = 'cancelled', plan = 'free', updated_at = ? WHERE clerk_user_id = ?",
            (_now_iso(), clerk_user_id),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Budgets (spend guardrails)
    # ------------------------------------------------------------------

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
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO budgets
               (budget_id, tenant_id, name, scope, service, monthly_limit_usd,
                alert_thresholds, action_on_breach, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (budget_id, tenant_id, name, scope, service, monthly_limit_usd,
             thresholds, action_on_breach, now, now),
        )
        self.conn.commit()
        return self.get_budget(budget_id, tenant_id)  # type: ignore

    def get_budget(self, budget_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM budgets WHERE budget_id = ? AND tenant_id = ?",
            (budget_id, tenant_id),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["alert_thresholds"] = json.loads(d.get("alert_thresholds") or "[]")
        return d

    def list_budgets(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM budgets WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["alert_thresholds"] = json.loads(d.get("alert_thresholds") or "[]")
            result.append(d)
        return result

    def update_budget(
        self,
        budget_id: str,
        tenant_id: str,
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        allowed = {"name", "monthly_limit_usd", "alert_thresholds", "action_on_breach", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return self.get_budget(budget_id, tenant_id)
        if "alert_thresholds" in updates:
            updates["alert_thresholds"] = json.dumps(updates["alert_thresholds"])
        updates["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [budget_id, tenant_id]
        self.conn.execute(
            f"UPDATE budgets SET {set_clause} WHERE budget_id = ? AND tenant_id = ?",
            vals,
        )
        self.conn.commit()
        return self.get_budget(budget_id, tenant_id)

    def delete_budget(self, budget_id: str, tenant_id: str) -> bool:
        cur = self.conn.cursor()
        cur.execute(
            "DELETE FROM budgets WHERE budget_id = ? AND tenant_id = ?",
            (budget_id, tenant_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def record_budget_alert(
        self,
        tenant_id: str,
        budget_id: str,
        threshold_pct: int,
        current_spend: float,
        budget_limit: float,
    ) -> str:
        alert_id = str(uuid.uuid4())
        now = _now_iso()
        self.conn.execute(
            """INSERT INTO budget_alerts
               (alert_id, tenant_id, budget_id, threshold_pct, current_spend_usd,
                budget_limit_usd, triggered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (alert_id, tenant_id, budget_id, threshold_pct, current_spend, budget_limit, now),
        )
        self.conn.commit()
        return alert_id

    def list_budget_alerts(self, tenant_id: str, budget_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        if budget_id:
            rows = self.conn.execute(
                "SELECT * FROM budget_alerts WHERE tenant_id = ? AND budget_id = ? ORDER BY triggered_at DESC LIMIT ?",
                (tenant_id, budget_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM budget_alerts WHERE tenant_id = ? ORDER BY triggered_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_last_budget_alert(self, tenant_id: str, budget_id: str, threshold_pct: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            """SELECT * FROM budget_alerts
               WHERE tenant_id = ? AND budget_id = ? AND threshold_pct = ?
               ORDER BY triggered_at DESC LIMIT 1""",
            (tenant_id, budget_id, threshold_pct),
        ).fetchone()
        return dict(row) if row else None

    def get_current_month_spend(self, tenant_id: str, service: Optional[str] = None) -> float:
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        if service:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0) as total FROM cost_snapshots WHERE tenant_id = ? AND service = ? AND hour >= ?",
                (tenant_id, service, month_start),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0) as total FROM cost_snapshots WHERE tenant_id = ? AND hour >= ?",
                (tenant_id, month_start),
            ).fetchone()
        return float(row["total"]) if row else 0.0

    # ------------------------------------------------------------------
    # Team Members
    # ------------------------------------------------------------------

    def invite_team_member(
        self,
        tenant_id: str,
        email: str,
        role: str = "viewer",
        name: Optional[str] = None,
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        member_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """INSERT INTO team_members
               (member_id, tenant_id, email, name, role, invited_by, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (member_id, tenant_id, email, name, role, invited_by, now, now),
        )
        self.conn.commit()
        return self.get_team_member(tenant_id, member_id)

    def list_team_members(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM team_members WHERE tenant_id = ? ORDER BY created_at",
            (tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_team_member(self, tenant_id: str, member_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM team_members WHERE tenant_id = ? AND member_id = ?",
            (tenant_id, member_id),
        ).fetchone()
        return dict(row) if row else None

    def update_team_member(
        self,
        tenant_id: str,
        member_id: str,
        role: Optional[str] = None,
        status: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        fields, params = [], []
        if role is not None:
            fields.append("role = ?"); params.append(role)
        if status is not None:
            fields.append("status = ?"); params.append(status)
        if name is not None:
            fields.append("name = ?"); params.append(name)
        if not fields:
            return self.get_team_member(tenant_id, member_id)
        fields.append("updated_at = ?"); params.append(now)
        params += [tenant_id, member_id]
        self.conn.execute(
            f"UPDATE team_members SET {', '.join(fields)} WHERE tenant_id = ? AND member_id = ?",
            params,
        )
        self.conn.commit()
        return self.get_team_member(tenant_id, member_id)

    def delete_team_member(self, tenant_id: str, member_id: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM team_members WHERE tenant_id = ? AND member_id = ?",
            (tenant_id, member_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    # ── Virtual Tags ──────────────────────────────────────────────────────────

    def create_virtual_tag(self, tenant_id: str, name: str, color: str = "#6366f1", rules: list = None) -> str:
        import uuid
        tag_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        import json as _json
        self.conn.execute(
            "INSERT INTO virtual_tags (tag_id, tenant_id, name, color, rules, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (tag_id, tenant_id, name, color, _json.dumps(rules or []), now, now),
        )
        self.conn.commit()
        return tag_id

    def list_virtual_tags(self, tenant_id: str) -> list:
        import json as _json
        rows = self.conn.execute(
            "SELECT * FROM virtual_tags WHERE tenant_id = ? ORDER BY name",
            (tenant_id,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try: d["rules"] = _json.loads(d.get("rules") or "[]")
            except Exception: d["rules"] = []
            result.append(d)
        return result

    def get_virtual_tag(self, tenant_id: str, tag_id: str) -> Optional[Dict[str, Any]]:
        import json as _json
        row = self.conn.execute(
            "SELECT * FROM virtual_tags WHERE tenant_id = ? AND tag_id = ?",
            (tenant_id, tag_id)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        try: d["rules"] = _json.loads(d.get("rules") or "[]")
        except Exception: d["rules"] = []
        return d

    def update_virtual_tag(self, tenant_id: str, tag_id: str, name: str = None, color: str = None, rules: list = None) -> Optional[Dict[str, Any]]:
        import json as _json
        now = datetime.now(timezone.utc).isoformat()
        fields, params = [], []
        if name is not None: fields.append("name = ?"); params.append(name)
        if color is not None: fields.append("color = ?"); params.append(color)
        if rules is not None: fields.append("rules = ?"); params.append(_json.dumps(rules))
        if not fields:
            return self.get_virtual_tag(tenant_id, tag_id)
        fields.append("updated_at = ?"); params.append(now)
        params += [tenant_id, tag_id]
        self.conn.execute(
            f"UPDATE virtual_tags SET {', '.join(fields)} WHERE tenant_id = ? AND tag_id = ?",
            params,
        )
        self.conn.commit()
        return self.get_virtual_tag(tenant_id, tag_id)

    def delete_virtual_tag(self, tenant_id: str, tag_id: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM virtual_tags WHERE tenant_id = ? AND tag_id = ?",
            (tenant_id, tag_id)
        )
        self.conn.commit()
        return cur.rowcount > 0

    # ── Kubernetes cost records ────────────────────────────────────────────────

    def ingest_k8s_cost_records(self, tenant_id: str, records: list) -> int:
        import uuid, json as _json
        now_iso = datetime.now(timezone.utc).isoformat()
        count = 0
        for rec in records:
            rec_id = str(uuid.uuid4())
            hour = rec.get("hour") or now_iso[:13] + ":00:00"
            self.conn.execute(
                """INSERT OR REPLACE INTO k8s_cost_records
                   (id, tenant_id, cluster, namespace, pod, container, node,
                    cpu_cores, mem_gib, cpu_cost_usd, mem_cost_usd, total_cost_usd, hour, labels)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rec.get("id") or rec_id,
                    tenant_id,
                    rec.get("cluster", "default"),
                    rec.get("namespace", "default"),
                    rec.get("pod"),
                    rec.get("container"),
                    rec.get("node"),
                    float(rec.get("cpu_cores", 0)),
                    float(rec.get("mem_gib", 0)),
                    float(rec.get("cpu_cost_usd", 0)),
                    float(rec.get("mem_cost_usd", 0)),
                    float(rec.get("total_cost_usd", 0)),
                    hour,
                    _json.dumps(rec.get("labels") or {}),
                ),
            )
            count += 1
        self.conn.commit()
        return count

    def list_k8s_cost_records(self, tenant_id: str, cluster: str = None, namespace: str = None,
                               hours_back: int = 168, limit: int = 10000) -> list:
        import json as _json
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()[:13]
        query = "SELECT * FROM k8s_cost_records WHERE tenant_id = ? AND hour >= ?"
        params: list = [tenant_id, cutoff + ":00:00"]
        if cluster:
            query += " AND cluster = ?"; params.append(cluster)
        if namespace:
            query += " AND namespace = ?"; params.append(namespace)
        query += f" ORDER BY hour DESC LIMIT {int(limit)}"
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try: d["labels"] = _json.loads(d.get("labels") or "{}")
            except Exception: d["labels"] = {}
            result.append(d)
        return result

    def get_k8s_cost_summary(self, tenant_id: str, hours_back: int = 168) -> dict:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()[:13] + ":00:00"
        # By namespace
        ns_rows = self.conn.execute(
            """SELECT cluster, namespace,
                      SUM(cpu_cost_usd) as cpu_cost, SUM(mem_cost_usd) as mem_cost,
                      SUM(total_cost_usd) as total_cost
               FROM k8s_cost_records
               WHERE tenant_id = ? AND hour >= ?
               GROUP BY cluster, namespace
               ORDER BY total_cost DESC""",
            (tenant_id, cutoff)
        ).fetchall()
        # By cluster
        cl_rows = self.conn.execute(
            """SELECT cluster, SUM(total_cost_usd) as total_cost
               FROM k8s_cost_records
               WHERE tenant_id = ? AND hour >= ?
               GROUP BY cluster
               ORDER BY total_cost DESC""",
            (tenant_id, cutoff)
        ).fetchall()
        total = sum(float(r["total_cost"] or 0) for r in cl_rows)
        return {
            "total_cost_usd": round(total, 4),
            "by_cluster": [{"cluster": r["cluster"], "total_cost_usd": round(float(r["total_cost"] or 0), 4)} for r in cl_rows],
            "by_namespace": [
                {
                    "cluster": r["cluster"],
                    "namespace": r["namespace"],
                    "cpu_cost_usd": round(float(r["cpu_cost"] or 0), 4),
                    "mem_cost_usd": round(float(r["mem_cost"] or 0), 4),
                    "total_cost_usd": round(float(r["total_cost"] or 0), 4),
                }
                for r in ns_rows
            ],
        }
