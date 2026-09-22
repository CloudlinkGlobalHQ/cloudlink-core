import sys
from pathlib import Path

# Make cloudlink-core importable from test files
CORE = Path(__file__).resolve().parent.parent
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


import pytest as _pytest


@_pytest.fixture(autouse=True)
def _postgres_backend(monkeypatch):
    """Set CLOUDLINK_TEST_PG_URL to run the store tests against Postgres (fresh schema per test)."""
    import os

    url = os.environ.get("CLOUDLINK_TEST_PG_URL", "").strip()
    if not url:
        yield
        return
    import psycopg2
    from cloudlink_core.state import pg_compat, sqlite_store

    raw = psycopg2.connect(url)
    raw.autocommit = True
    with raw.cursor() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    raw.close()
    for conn in list(pg_compat._raw_conns.values()):
        conn.close()
    pg_compat._raw_conns.clear()
    pg_compat._pk_cache.clear()
    pg_compat._done_scripts.clear()
    sqlite_store._PG_SCHEMA_READY.clear()
    monkeypatch.setenv("DATABASE_URL", url)
    yield
