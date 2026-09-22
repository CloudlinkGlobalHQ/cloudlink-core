"""pg_compat: SQLite-dialect SQL over Postgres. Live tests need CLOUDLINK_TEST_PG_URL."""
import os
import sqlite3

import pytest

from cloudlink_core.state import pg_compat
from cloudlink_core.state.pg_compat import translate

PG_URL = os.environ.get("CLOUDLINK_TEST_PG_URL", "").strip()
live = pytest.mark.skipif(not PG_URL, reason="CLOUDLINK_TEST_PG_URL not set")


def test_translate_dialect():
    assert "BIGSERIAL PRIMARY KEY" in translate("id INTEGER PRIMARY KEY AUTOINCREMENT")
    assert "now()" in translate("created_at TEXT DEFAULT (datetime('now'))")
    assert "string_agg((id)::text, ',')" in translate("SELECT GROUP_CONCAT(id) FROM t")
    assert translate("INSERT OR IGNORE INTO t (a) VALUES (?)").endswith("ON CONFLICT DO NOTHING")
    assert translate("INSERT OR REPLACE INTO t (a, b) VALUES (?, ?)", ["a"]).endswith(
        "ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b"
    )
    assert "gen_random_uuid" in translate("id TEXT DEFAULT (lower(hex(randomblob(16))))")


def test_placeholders_skip_string_literals():
    assert pg_compat._replace_placeholders("SELECT '?', x FROM t WHERE a = ? AND b LIKE '5%'") == \
        "SELECT '?', x FROM t WHERE a = %s AND b LIKE '5%%'"


@pytest.fixture()
def conn():
    import psycopg2

    raw = psycopg2.connect(PG_URL)
    raw.autocommit = True
    with raw.cursor() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    raw.close()
    pg_compat._raw_conns.clear()
    pg_compat._pk_cache.clear()
    pg_compat._done_scripts.clear()
    return pg_compat.connect(PG_URL)


@live
def test_roundtrip(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS kv (
            tenant_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT, n INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (tenant_id, key));
        CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT, amt REAL);
    """)
    conn.execute("INSERT OR REPLACE INTO kv (tenant_id, key, value, n) VALUES (?,?,?,?)", ("t", "k", "v1", True))
    conn.execute("INSERT OR REPLACE INTO kv (tenant_id, key, value, n) VALUES (?,?,?,?)", ("t", "k", "v2", 5))
    conn.execute("INSERT OR IGNORE INTO kv (tenant_id, key, value) VALUES (?,?,?)", ("t", "k", "ignored"))
    row = conn.execute("SELECT * FROM kv WHERE tenant_id = ? AND n = ?", ("t", "5")).fetchone()
    assert row["value"] == "v2" and row[2] == "v2" and dict(row)["n"] == 5
    assert len(row["created_at"]) == 19

    cur = conn.cursor()
    cur.executemany("INSERT INTO log (msg, amt) VALUES (?, ?)", [("a", 1.5), ("b", 2)])
    agg = conn.execute("SELECT GROUP_CONCAT(id) AS ids, SUM(amt) AS total, COUNT(*) AS c FROM log").fetchone()
    assert agg["ids"] == "1,2" and agg["total"] == 3.5 and isinstance(agg["c"], int)

    cols = {r["name"] for r in conn.execute("PRAGMA table_info(kv)").fetchall()}
    assert {"tenant_id", "key", "value", "n", "created_at"} <= cols
    assert conn.execute("PRAGMA journal_mode=WAL").fetchall() == []

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO kv (tenant_id, key) VALUES (?, ?)", ("t", "k"))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("ALTER TABLE kv ADD COLUMN value TEXT")
    # a failed statement must not break the session
    assert conn.execute("SELECT COUNT(*) FROM kv").fetchone()[0] == 1


@live
def test_reconnects_after_server_drops_connection(conn):
    import psycopg2

    conn.execute("SELECT 1").fetchone()
    pid = conn.execute("SELECT pg_backend_pid()").fetchone()[0]
    killer = psycopg2.connect(PG_URL)
    killer.autocommit = True
    with killer.cursor() as c:
        c.execute("SELECT pg_terminate_backend(%s)", (pid,))
    killer.close()
    assert conn.execute("SELECT 2").fetchone()[0] == 2


@live
def test_created_tables_have_rls(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, v TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, v TEXT)")  # idempotent
    conn.execute("INSERT INTO secrets (id, v) VALUES (?, ?)", ("a", "b"))
    assert conn.execute("SELECT relrowsecurity FROM pg_class WHERE relname = 'secrets'").fetchone()[0] is True
    assert conn.execute("SELECT v FROM secrets").fetchone()["v"] == "b"  # owner still reads
