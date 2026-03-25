from __future__ import annotations

import hashlib
import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class PostgresIdentityStore:
    """
    Minimal Postgres-backed store for tenants and API keys.

    This lets auth and tenant lifecycle move onto Railway Postgres ahead of the
    larger operational-state migration.
    """

    DEFAULT_TENANT = "default"

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresIdentityStore")

        import psycopg2  # type: ignore
        from psycopg2.extras import RealDictCursor  # type: ignore

        self._psycopg2 = psycopg2
        self._cursor_factory = RealDictCursor
        self._ensure_schema()
        self.seed_default_tenant()

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
                    CREATE TABLE IF NOT EXISTS tenants (
                        tenant_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        created_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS api_keys (
                        key_hash TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        label TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_api_keys_tenant
                    ON api_keys(tenant_id)
                    """
                )
            conn.commit()

    def seed_default_tenant(self) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tenants (tenant_id, name, status, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id) DO NOTHING
                    """,
                    (self.DEFAULT_TENANT, "Default Tenant", "active", _now_iso()),
                )
            conn.commit()

    def create_tenant(self, name: str) -> str:
        tenant_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tenants (tenant_id, name, status, created_at)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (tenant_id, name, "active", _now_iso()),
                )
            conn.commit()
        return tenant_id

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute("SELECT * FROM tenants WHERE tenant_id = %s", (tenant_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute("SELECT * FROM tenants ORDER BY created_at")
                return [dict(r) for r in cur.fetchall()]

    def add_api_key(self, tenant_id: str, raw_key: str, label: Optional[str] = None) -> str:
        key_hash = _hash_api_key(raw_key)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO api_keys (key_hash, tenant_id, label, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (key_hash) DO NOTHING
                    """,
                    (key_hash, tenant_id, label, _now_iso()),
                )
            conn.commit()
        return key_hash

    def get_tenant_id_for_api_key(self, raw_key: str) -> Optional[str]:
        key_hash = _hash_api_key(raw_key)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT tenant_id FROM api_keys WHERE key_hash = %s", (key_hash,))
                row = cur.fetchone()
                return row[0] if row else None
