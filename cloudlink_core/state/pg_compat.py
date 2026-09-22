"""
Postgres connection that speaks the sqlite3 API and SQLite's SQL dialect.

SQLiteStateStore (and the API's raw SQL) was written against sqlite3. Rather
than maintaining two copies of every query, `connect(dsn)` returns an object
with the sqlite3.Connection surface (execute, executescript, cursor, commit,
row access by name or index) that rewrites the small set of SQLite-only
constructs we use into Postgres:

  ?                               -> %s
  INSERT OR IGNORE                -> ON CONFLICT DO NOTHING
  INSERT OR REPLACE               -> ON CONFLICT (<pk>) DO UPDATE SET ...
  INTEGER PRIMARY KEY [AUTOINCREMENT] -> BIGSERIAL PRIMARY KEY
  datetime('now')                 -> UTC timestamp text
  GROUP_CONCAT(x)                 -> string_agg(x::text, ',')
  lower(hex(randomblob(16)))      -> gen_random_uuid() hex
  BLOB                            -> BYTEA
  PRAGMA table_info(t)            -> information_schema query
  other PRAGMAs                   -> no-op

Parameters are sent as untyped literals so Postgres coerces them the way
SQLite would (e.g. comparing an INTEGER column with '1'). Numeric results come
back as int/float, never Decimal. psycopg2 errors are re-raised as the
matching sqlite3 exceptions so existing `except sqlite3.IntegrityError`
handlers keep working.

The connection runs in autocommit mode: SQLite code commits after nearly every
statement anyway, and it keeps a failed statement (e.g. a duplicate ALTER
TABLE ADD COLUMN) from poisoning the rest of the session.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import psycopg2
import psycopg2.errors
import psycopg2.extensions

_NOW_SQL = "to_char(timezone('UTC', now()), 'YYYY-MM-DD HH24:MI:SS')"

_lock = threading.Lock()
_raw_conns: Dict[str, Any] = {}
_pk_cache: Dict[Tuple[str, str], List[str]] = {}
_done_scripts: Dict[str, set] = {}


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

class Row(tuple):
    """sqlite3.Row lookalike: index by position or column name, dict(row) works."""

    _keys: Tuple[str, ...] = ()

    def __new__(cls, values: Sequence[Any], keys: Tuple[str, ...], index: Dict[str, int]):
        r = super().__new__(cls, values)
        r._keys = keys
        r._index = index
        return r

    def __getitem__(self, key):  # type: ignore[override]
        if isinstance(key, str):
            try:
                return tuple.__getitem__(self, self._index[key.lower()])
            except KeyError:
                raise IndexError(f"No item with that key: {key}") from None
        return tuple.__getitem__(self, key)

    def keys(self) -> List[str]:
        return list(self._keys)


def _clean(v: Any) -> Any:
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, memoryview):
        return bytes(v)
    return v


# ---------------------------------------------------------------------------
# SQL translation
# ---------------------------------------------------------------------------

_RE_INSERT_OR = re.compile(r"^\s*INSERT\s+OR\s+(IGNORE|REPLACE)\s+INTO\s+", re.I)
_RE_INSERT_COLS = re.compile(r"INTO\s+([\w\"]+)\s*\(([^)]*)\)", re.I | re.S)
_RE_PK_AUTO = re.compile(r"\bINTEGER\s+PRIMARY\s+KEY(\s+AUTOINCREMENT)?\b", re.I)
_RE_NOW = re.compile(r"datetime\(\s*'now'\s*\)", re.I)
_RE_DATE_NOW = re.compile(r"\bdate\(\s*'now'\s*\)", re.I)
_RE_GROUP_CONCAT = re.compile(r"GROUP_CONCAT\(\s*([^)]+?)\s*\)", re.I)
_RE_RANDOM_HEX = re.compile(r"lower\(\s*hex\(\s*randomblob\(\s*16\s*\)\s*\)\s*\)", re.I)
_RE_BLOB = re.compile(r"\bBLOB\b", re.I)
_RE_PRAGMA = re.compile(r"^\s*PRAGMA\s+(\w+)\s*(?:\(\s*([\w\"]+)\s*\))?", re.I)


def _replace_placeholders(sql: str) -> str:
    """Swap ? for %s and escape literal % — both only outside string literals."""
    out = []
    in_str = False
    for ch in sql:
        if ch == "'":
            in_str = not in_str
            out.append(ch)
        elif ch == "?" and not in_str:
            out.append("%s")
        elif ch == "%":
            out.append("%%")
        else:
            out.append(ch)
    return "".join(out)


def translate(sql: str, conflict_cols: Optional[List[str]] = None) -> str:
    sql = _RE_PK_AUTO.sub("BIGSERIAL PRIMARY KEY", sql)
    sql = _RE_NOW.sub(_NOW_SQL, sql)
    sql = _RE_DATE_NOW.sub("to_char(timezone('UTC', now()), 'YYYY-MM-DD')", sql)
    sql = _RE_GROUP_CONCAT.sub(r"string_agg((\1)::text, ',')", sql)
    sql = _RE_RANDOM_HEX.sub("replace(gen_random_uuid()::text, '-', '')", sql)
    sql = _RE_BLOB.sub("BYTEA", sql)

    m = _RE_INSERT_OR.match(sql)
    if m:
        mode = m.group(1).upper()
        sql = "INSERT INTO " + sql[m.end():]
        body = sql.rstrip().rstrip(";")
        if mode == "IGNORE":
            sql = body + " ON CONFLICT DO NOTHING"
        else:
            cols_m = _RE_INSERT_COLS.search(body)
            cols = [c.strip().strip('"') for c in cols_m.group(2).split(",")] if cols_m else []
            target = conflict_cols or []
            updates = [c for c in cols if c not in target]
            if target and updates:
                sets = ", ".join(f"{c} = EXCLUDED.{c}" for c in updates)
                sql = f"{body} ON CONFLICT ({', '.join(target)}) DO UPDATE SET {sets}"
            else:
                sql = body + " ON CONFLICT DO NOTHING"
    return sql


def _split_script(script: str) -> List[str]:
    parts, buf, in_str = [], [], False
    for ch in script:
        if ch == "'":
            in_str = not in_str
        if ch == ";" and not in_str:
            stmt = "".join(buf).strip()
            if stmt:
                parts.append(stmt)
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _adapt_params(params: Any) -> Any:
    if params is None:
        return None
    if isinstance(params, dict):
        return {k: _adapt_value(v) for k, v in params.items()}
    return tuple(_adapt_value(v) for v in params)


def _adapt_value(v: Any) -> Any:
    # Send scalars as quoted literals (type "unknown") so Postgres infers the
    # type from the column, like SQLite's loose typing.
    if v is None or isinstance(v, (bytes, bytearray, memoryview)):
        return v
    if isinstance(v, bool):
        return str(int(v))
    if isinstance(v, (int, float, Decimal)):
        return repr(v) if isinstance(v, float) else str(v)
    return v


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def _to_sqlite_error(exc: Exception) -> Exception:
    if isinstance(exc, psycopg2.IntegrityError):
        return sqlite3.IntegrityError(str(exc))
    if isinstance(exc, (psycopg2.OperationalError, psycopg2.ProgrammingError)):
        return sqlite3.OperationalError(str(exc))
    if isinstance(exc, psycopg2.DataError):
        return sqlite3.DataError(str(exc))
    return sqlite3.DatabaseError(str(exc))


# ---------------------------------------------------------------------------
# Connection / cursor
# ---------------------------------------------------------------------------

def _open(dsn: str):
    raw = psycopg2.connect(dsn)
    raw.autocommit = True
    return raw


class Cursor:
    def __init__(self, conn: "Connection"):
        self._conn = conn
        self._rows: List[Row] = []
        self._pos = 0
        self.rowcount = -1
        self.description = None
        self.lastrowid = None

    def execute(self, sql: str, params: Any = None) -> "Cursor":
        self._rows, self._pos = self._conn._run(sql, params, self)
        return self

    def executemany(self, sql: str, seq: Iterable[Any]) -> "Cursor":
        total = 0
        for p in seq:
            self.execute(sql, p)
            total += max(self.rowcount, 0)
        self.rowcount = total
        return self

    def executescript(self, script: str) -> "Cursor":
        self._conn.executescript(script)
        return self

    def fetchone(self) -> Optional[Row]:
        if self._pos >= len(self._rows):
            return None
        r = self._rows[self._pos]
        self._pos += 1
        return r

    def fetchall(self) -> List[Row]:
        rows = self._rows[self._pos:]
        self._pos = len(self._rows)
        return rows

    def fetchmany(self, size: int = 1) -> List[Row]:
        rows = self._rows[self._pos:self._pos + size]
        self._pos += len(rows)
        return rows

    def __iter__(self):
        while True:
            r = self.fetchone()
            if r is None:
                return
            yield r

    def close(self) -> None:
        self._rows = []


class Connection:
    """sqlite3.Connection-compatible wrapper around a shared psycopg2 connection."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.row_factory = None  # accepted for compatibility; rows are always Row
        self.total_changes = 0

    # -- plumbing ----------------------------------------------------------
    def _raw(self):
        with _lock:
            raw = _raw_conns.get(self.dsn)
            if raw is None or raw.closed:
                raw = _open(self.dsn)
                _raw_conns[self.dsn] = raw
            return raw

    def _reset(self) -> None:
        with _lock:
            raw = _raw_conns.pop(self.dsn, None)
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass

    def _primary_key(self, table: str) -> List[str]:
        key = (self.dsn, table.lower())
        if key not in _pk_cache:
            rows, _ = self._run(
                """SELECT a.attname FROM pg_index i
                   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                   WHERE i.indrelid = to_regclass(?) AND i.indisprimary""",
                (table,), None, raw_sql=False,
            )
            cols = [r[0] for r in rows]
            if not cols:  # fall back to the first unique index
                rows, _ = self._run(
                    """SELECT a.attname FROM pg_index i
                       JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                       WHERE i.indrelid = to_regclass(?) AND i.indisunique
                       ORDER BY i.indexrelid, array_position(i.indkey::int2[], a.attnum)""",
                    (table,), None, raw_sql=False,
                )
                cols = [r[0] for r in rows]
            _pk_cache[key] = cols
        return _pk_cache[key]

    def _pragma(self, name: str, arg: Optional[str], cur: Optional[Cursor]):
        if name.lower() != "table_info" or not arg:
            return [], 0
        return self._run(
            """SELECT ordinal_position - 1 AS cid, column_name AS name, data_type AS type,
                      CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull,
                      column_default AS dflt_value, 0 AS pk
               FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = ?
               ORDER BY ordinal_position""",
            (arg.strip('"').lower(),), cur, raw_sql=False,
        )

    def _run(self, sql: str, params: Any, cur: Optional[Cursor], raw_sql: bool = True):
        if raw_sql:
            pm = _RE_PRAGMA.match(sql)
            if pm:
                return self._pragma(pm.group(1), pm.group(2), cur)
            conflict = None
            m = _RE_INSERT_OR.match(sql)
            if m and m.group(1).upper() == "REPLACE":
                cols_m = _RE_INSERT_COLS.search(sql)
                if cols_m:
                    conflict = self._primary_key(cols_m.group(1).strip('"'))
            sql = translate(sql, conflict)
        pg_sql = _replace_placeholders(sql) if params is not None else sql
        args = _adapt_params(params)

        for attempt in (0, 1):
            raw = self._raw()
            try:
                with raw.cursor() as c:
                    c.execute(pg_sql, args)
                    rows: List[Row] = []
                    if c.description:
                        names = tuple(d[0] for d in c.description)
                        index = {n.lower(): i for i, n in enumerate(names)}
                        rows = [Row([_clean(v) for v in r], names, index) for r in c.fetchall()]
                    if cur is not None:
                        cur.rowcount = c.rowcount
                        cur.description = c.description
                    if c.rowcount and c.rowcount > 0 and not c.description:
                        self.total_changes += c.rowcount
                    return rows, 0
            except (psycopg2.InterfaceError, psycopg2.OperationalError) as exc:
                # Dropped connection (e.g. a hosted DB closing idle sessions): reconnect once.
                if attempt == 0 and (raw.closed or isinstance(exc, psycopg2.InterfaceError)):
                    self._reset()
                    continue
                raise _to_sqlite_error(exc) from exc
            except psycopg2.Error as exc:
                raise _to_sqlite_error(exc) from exc
        raise sqlite3.OperationalError("database connection lost")

    # -- sqlite3.Connection surface ---------------------------------------
    def cursor(self) -> Cursor:
        return Cursor(self)

    def execute(self, sql: str, params: Any = None) -> Cursor:
        return self.cursor().execute(sql, params)

    def executemany(self, sql: str, seq: Iterable[Any]) -> Cursor:
        return self.cursor().executemany(sql, seq)

    def executescript(self, script: str) -> Cursor:
        # Schema scripts run on every request in places; do each one once per process.
        stmts = _split_script(script)
        idempotent = all(re.match(r"\s*CREATE\s+(TABLE|INDEX|UNIQUE\s+INDEX)\s+IF\s+NOT\s+EXISTS", s, re.I) for s in stmts)
        done = _done_scripts.setdefault(self.dsn, set())
        if idempotent and script in done:
            return self.cursor()
        for s in stmts:
            self.execute(s)
        if idempotent:
            done.add(script)
        return self.cursor()

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        # The underlying connection is shared per process; nothing to do.
        pass

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *exc) -> bool:
        return False


def connect(dsn: str) -> Connection:
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://"):]
    return Connection(dsn)


def is_postgres_url(url: Optional[str]) -> bool:
    return bool(url) and url.strip().startswith(("postgres://", "postgresql://"))
