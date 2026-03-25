from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from cloudlink_core.state.crypto import decrypt_credential, encrypt_credential


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class PostgresCredentialStore:
    """
    Minimal Postgres-backed credential store.

    Credentials stay encrypted at rest using the existing Cloudlink encryption
    helpers; only the storage backend changes.
    """

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresCredentialStore")

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
                    CREATE TABLE IF NOT EXISTS cloud_credentials (
                        credential_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        cloud TEXT NOT NULL,
                        label TEXT,
                        credential_type TEXT NOT NULL,
                        encrypted_payload TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_verified_at TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_credentials_tenant
                    ON cloud_credentials(tenant_id)
                    """
                )
            conn.commit()

    def add_credential(
        self,
        tenant_id: str,
        cloud: str,
        credential_type: str,
        payload: str,
        label: Optional[str] = None,
    ) -> str:
        credential_id = str(uuid.uuid4())
        encrypted = encrypt_credential(payload)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cloud_credentials
                    (credential_id, tenant_id, cloud, label, credential_type, encrypted_payload, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (credential_id, tenant_id, cloud, label, credential_type, encrypted, _now_iso()),
                )
            conn.commit()
        return credential_id

    def list_credentials(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT credential_id, tenant_id, cloud, label, credential_type, created_at, last_verified_at
                    FROM cloud_credentials
                    WHERE tenant_id = %s
                    ORDER BY created_at
                    """,
                    (tenant_id,),
                )
                return [dict(r) for r in cur.fetchall()]

    def get_decrypted_credential(self, tenant_id: str, credential_id: str) -> Optional[str]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT encrypted_payload
                    FROM cloud_credentials
                    WHERE credential_id = %s AND tenant_id = %s
                    """,
                    (credential_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return decrypt_credential(row[0])

    def delete_credential(self, tenant_id: str, credential_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM cloud_credentials
                    WHERE credential_id = %s AND tenant_id = %s
                    """,
                    (credential_id, tenant_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def mark_credential_verified(self, tenant_id: str, credential_id: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE cloud_credentials
                    SET last_verified_at = %s
                    WHERE credential_id = %s AND tenant_id = %s
                    """,
                    (_now_iso(), credential_id, tenant_id),
                )
            conn.commit()
