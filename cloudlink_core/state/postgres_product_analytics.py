from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostgresProductAnalyticsStore:
    """Postgres-backed virtual tags and Kubernetes cost analytics."""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = (dsn or os.environ.get("DATABASE_URL", "")).strip()
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresProductAnalyticsStore")

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
                    CREATE TABLE IF NOT EXISTS virtual_tags (
                        tag_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        color TEXT NOT NULL,
                        rules TEXT NOT NULL DEFAULT '[]',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_virtual_tags_tenant
                    ON virtual_tags(tenant_id)
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS k8s_cost_records (
                        id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        cluster TEXT NOT NULL,
                        namespace TEXT NOT NULL,
                        pod TEXT,
                        container TEXT,
                        node TEXT,
                        cpu_cores DOUBLE PRECISION NOT NULL DEFAULT 0,
                        mem_gib DOUBLE PRECISION NOT NULL DEFAULT 0,
                        cpu_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
                        mem_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
                        total_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
                        hour TEXT NOT NULL,
                        labels TEXT NOT NULL DEFAULT '{}'
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_k8s_cost_tenant_hour
                    ON k8s_cost_records(tenant_id, hour)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_k8s_cost_namespace
                    ON k8s_cost_records(tenant_id, cluster, namespace)
                    """
                )
            conn.commit()

    def create_virtual_tag(self, tenant_id: str, name: str, color: str = "#6366f1", rules: list | None = None) -> str:
        tag_id = str(uuid.uuid4())
        now = _now_iso()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO virtual_tags (tag_id, tenant_id, name, color, rules, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (tag_id, tenant_id, name, color, json.dumps(rules or []), now, now),
                )
            conn.commit()
        return tag_id

    def list_virtual_tags(self, tenant_id: str) -> list:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute("SELECT * FROM virtual_tags WHERE tenant_id = %s ORDER BY name", (tenant_id,))
                rows = []
                for row in cur.fetchall():
                    d = dict(row)
                    d["rules"] = json.loads(d.get("rules") or "[]")
                    rows.append(d)
                return rows

    def get_virtual_tag(self, tenant_id: str, tag_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute("SELECT * FROM virtual_tags WHERE tenant_id = %s AND tag_id = %s", (tenant_id, tag_id))
                row = cur.fetchone()
                if not row:
                    return None
                d = dict(row)
                d["rules"] = json.loads(d.get("rules") or "[]")
                return d

    def update_virtual_tag(self, tenant_id: str, tag_id: str, name: str = None, color: str = None, rules: list = None) -> Optional[Dict[str, Any]]:
        fields: list[str] = []
        params: list[Any] = []
        if name is not None:
            fields.append("name = %s")
            params.append(name)
        if color is not None:
            fields.append("color = %s")
            params.append(color)
        if rules is not None:
            fields.append("rules = %s")
            params.append(json.dumps(rules))
        if not fields:
            return self.get_virtual_tag(tenant_id, tag_id)
        fields.append("updated_at = %s")
        params.append(_now_iso())
        params.extend([tenant_id, tag_id])
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE virtual_tags SET {', '.join(fields)} WHERE tenant_id = %s AND tag_id = %s",
                    params,
                )
            conn.commit()
        return self.get_virtual_tag(tenant_id, tag_id)

    def delete_virtual_tag(self, tenant_id: str, tag_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM virtual_tags WHERE tenant_id = %s AND tag_id = %s", (tenant_id, tag_id))
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def ingest_k8s_cost_records(self, tenant_id: str, records: list) -> int:
        now_iso = _now_iso()
        count = 0
        with self._conn() as conn:
            with conn.cursor() as cur:
                for rec in records:
                    rec_id = str(rec.get("id") or uuid.uuid4())
                    hour = rec.get("hour") or now_iso[:13] + ":00:00"
                    cur.execute(
                        """
                        INSERT INTO k8s_cost_records
                        (id, tenant_id, cluster, namespace, pod, container, node,
                         cpu_cores, mem_gib, cpu_cost_usd, mem_cost_usd, total_cost_usd, hour, labels)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                          cluster = EXCLUDED.cluster,
                          namespace = EXCLUDED.namespace,
                          pod = EXCLUDED.pod,
                          container = EXCLUDED.container,
                          node = EXCLUDED.node,
                          cpu_cores = EXCLUDED.cpu_cores,
                          mem_gib = EXCLUDED.mem_gib,
                          cpu_cost_usd = EXCLUDED.cpu_cost_usd,
                          mem_cost_usd = EXCLUDED.mem_cost_usd,
                          total_cost_usd = EXCLUDED.total_cost_usd,
                          hour = EXCLUDED.hour,
                          labels = EXCLUDED.labels
                        """,
                        (
                            rec_id,
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
                            json.dumps(rec.get("labels") or {}),
                        ),
                    )
                    count += 1
            conn.commit()
        return count

    def list_k8s_cost_records(self, tenant_id: str, cluster: str = None, namespace: str = None, hours_back: int = 168, limit: int = 10000) -> list:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()[:13] + ":00:00"
        query = "SELECT * FROM k8s_cost_records WHERE tenant_id = %s AND hour >= %s"
        params: list[Any] = [tenant_id, cutoff]
        if cluster:
            query += " AND cluster = %s"
            params.append(cluster)
        if namespace:
            query += " AND namespace = %s"
            params.append(namespace)
        query += " ORDER BY hour DESC LIMIT %s"
        params.append(int(limit))
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(query, params)
                rows = []
                for row in cur.fetchall():
                    d = dict(row)
                    d["labels"] = json.loads(d.get("labels") or "{}")
                    rows.append(d)
                return rows

    def get_k8s_cost_summary(self, tenant_id: str, hours_back: int = 168) -> dict:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()[:13] + ":00:00"
        with self._conn() as conn:
            with conn.cursor(cursor_factory=self._cursor_factory) as cur:
                cur.execute(
                    """
                    SELECT cluster, namespace,
                           SUM(cpu_cost_usd) as cpu_cost, SUM(mem_cost_usd) as mem_cost,
                           SUM(total_cost_usd) as total_cost
                    FROM k8s_cost_records
                    WHERE tenant_id = %s AND hour >= %s
                    GROUP BY cluster, namespace
                    ORDER BY total_cost DESC
                    """,
                    (tenant_id, cutoff),
                )
                ns_rows = [dict(r) for r in cur.fetchall()]
                cur.execute(
                    """
                    SELECT cluster, SUM(total_cost_usd) as total_cost
                    FROM k8s_cost_records
                    WHERE tenant_id = %s AND hour >= %s
                    GROUP BY cluster
                    ORDER BY total_cost DESC
                    """,
                    (tenant_id, cutoff),
                )
                cl_rows = [dict(r) for r in cur.fetchall()]
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
