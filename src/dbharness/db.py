"""Database executors — the only component that holds real DB credentials.

The credential vault is deliberately thin: the gate is configured with the real
connection string, opens the pool itself, and executes the *rewritten* statement
on the agent's behalf. The agent authenticates to the gate with its own key and
never sees, and cannot exfiltrate, the database credentials.

Two backends ship:

* :class:`SqliteExecutor` — zero-infra, for local demos and the test suite.
* :class:`PostgresExecutor` — the real first-class target (requires ``asyncpg``,
  installed via the ``postgres`` extra).

Both implement :class:`Executor`, so the rest of the gate is backend-agnostic;
adding MySQL later is one new class plus a ``dialect`` string.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class QueryResult:
    columns: List[str]
    rows: List[List[Any]]

    @property
    def rowcount(self) -> int:
        return len(self.rows)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "columns": self.columns,
            "rows": [list(r) for r in self.rows],
            "row_count": self.rowcount,
        }


@dataclass
class WriteResult:
    rowcount: int

    def to_dict(self) -> Dict[str, Any]:
        return {"rows_affected": self.rowcount}


class Executor(abc.ABC):
    #: sqlglot dialect this backend speaks; the SqlGuard is built to match.
    dialect: str = "postgres"
    #: default schema used to normalize unqualified table names to schema.table.
    default_schema: str = "public"

    @abc.abstractmethod
    async def connect(self) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...

    @abc.abstractmethod
    async def query(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> QueryResult: ...

    @abc.abstractmethod
    async def execute(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> WriteResult: ...

    @abc.abstractmethod
    async def list_tables(self) -> List[str]: ...

    @abc.abstractmethod
    async def describe(self, table: str) -> List[Dict[str, str]]: ...

    async def run_script(self, sql: str) -> None:
        """Run one or more raw statements, bypassing the gate.

        Administrative only — used to seed a demo/test database. Not reachable
        from any agent-facing path.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# SQLite (demo / tests)
# ---------------------------------------------------------------------------


class SqliteExecutor(Executor):
    dialect = "sqlite"

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._conn = None  # type: ignore[assignment]

    @staticmethod
    def _strip_schema(table: str) -> str:
        # SQLite has no schemas; map "public.tickets" -> "tickets".
        return table.split(".")[-1]

    async def connect(self) -> None:
        import aiosqlite

        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def query(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> QueryResult:
        # SQLite has no per-session GUCs / RLS; `session` is accepted for
        # interface parity and ignored.
        assert self._conn is not None, "connect() first"
        cur = await self._conn.execute(sql)
        rows = await cur.fetchall()
        columns = [d[0] for d in (cur.description or [])]
        await cur.close()
        return QueryResult(columns=columns, rows=[list(r) for r in rows])

    async def execute(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> WriteResult:
        assert self._conn is not None, "connect() first"
        cur = await self._conn.execute(sql)
        await self._conn.commit()
        rowcount = cur.rowcount
        await cur.close()
        return WriteResult(rowcount=rowcount if rowcount is not None else 0)

    async def run_script(self, sql: str) -> None:
        assert self._conn is not None, "connect() first"
        await self._conn.executescript(sql)
        await self._conn.commit()

    async def list_tables(self) -> List[str]:
        res = await self.query(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [f"public.{r[0]}" for r in res.rows]

    async def describe(self, table: str) -> List[Dict[str, str]]:
        name = self._strip_schema(table)
        res = await self.query(f"PRAGMA table_info({name})")
        # PRAGMA columns: cid, name, type, notnull, dflt_value, pk
        cols = []
        for r in res.rows:
            cols.append({"name": str(r[1]), "type": str(r[2]), "nullable": not r[3]})
        return cols


# ---------------------------------------------------------------------------
# PostgreSQL (real target)
# ---------------------------------------------------------------------------


class PostgresExecutor(Executor):
    dialect = "postgres"

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10):
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self._pool = None  # type: ignore[assignment]

    async def connect(self) -> None:
        import asyncpg

        self._pool = await asyncpg.create_pool(
            self.dsn, min_size=self.min_size, max_size=self.max_size
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @staticmethod
    async def _apply_session(conn, session: "Optional[Dict[str, str]]") -> None:
        """Set transaction-local GUCs (must be inside a transaction).

        Uses ``set_config(name, value, is_local => true)`` with bound parameters
        so values can never be injected. These GUCs drive row-level-security
        policies (see postgres/rls.sql) — the database enforces tenant isolation
        as defense-in-depth even if a gate bug let an unfiltered query through.
        """
        for key, value in (session or {}).items():
            await conn.execute("SELECT set_config($1, $2, true)", key, value)

    async def query(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> QueryResult:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            if session:
                async with conn.transaction():
                    await self._apply_session(conn, session)
                    records = await conn.fetch(sql)
            else:
                records = await conn.fetch(sql)
        columns = list(records[0].keys()) if records else []
        rows = [list(r.values()) for r in records]
        return QueryResult(columns=columns, rows=rows)

    async def execute(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> WriteResult:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            if session:
                async with conn.transaction():
                    await self._apply_session(conn, session)
                    status = await conn.execute(sql)
            else:
                status = await conn.execute(sql)  # e.g. "UPDATE 3"
        rowcount = 0
        parts = status.split()
        if parts and parts[-1].isdigit():
            rowcount = int(parts[-1])
        return WriteResult(rowcount=rowcount)

    async def run_script(self, sql: str) -> None:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            await conn.execute(sql)

    async def list_tables(self) -> List[str]:
        res = await self.query(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
            "ORDER BY table_schema, table_name"
        )
        return [f"{r[0]}.{r[1]}" for r in res.rows]

    async def describe(self, table: str) -> List[Dict[str, str]]:
        parts = table.split(".")
        schema, name = (parts[0], parts[1]) if len(parts) == 2 else ("public", parts[0])
        res = await self.query(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            f"WHERE table_schema = '{schema}' AND table_name = '{name}' "
            "ORDER BY ordinal_position"
        )
        return [
            {"name": str(r[0]), "type": str(r[1]), "nullable": r[2] == "YES"}
            for r in res.rows
        ]


# ---------------------------------------------------------------------------
# MySQL / MariaDB
# ---------------------------------------------------------------------------


class MySQLExecutor(Executor):
    dialect = "mysql"

    def __init__(self, dsn: str, default_schema: Optional[str] = None):
        # dsn: mysql://user:pass@host:port/dbname
        self.dsn = dsn
        parsed = urlparse(dsn)
        self._host = parsed.hostname or "localhost"
        self._port = parsed.port or 3306
        self._user = parsed.username or "root"
        self._password = parsed.password or ""
        self._db = (parsed.path or "/").lstrip("/") or None
        # In MySQL the "schema" is the database; normalize table names against it
        # so a policy resource like "app.tickets" matches.
        self.default_schema = (default_schema or self._db or "def").lower()
        self._pool = None  # type: ignore[assignment]

    async def connect(self) -> None:
        import aiomysql

        self._pool = await aiomysql.create_pool(
            host=self._host, port=self._port, user=self._user,
            password=self._password, db=self._db, autocommit=True,
        )

    async def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None

    async def _set_session(self, cur, session: "Optional[Dict[str, str]]") -> None:
        # MySQL has no RLS; user-defined session variables are still set so a
        # deployment can key triggers/views on them if desired.
        for key, value in (session or {}).items():
            await cur.execute("SET @`%s` = %%s" % key.replace("`", ""), (value,))

    async def query(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> QueryResult:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await self._set_session(cur, session)
                await cur.execute(sql)
                rows = await cur.fetchall()
                columns = [d[0] for d in (cur.description or [])]
        return QueryResult(columns=columns, rows=[list(r) for r in rows])

    async def execute(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> WriteResult:
        assert self._pool is not None, "connect() first"
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await self._set_session(cur, session)
                await cur.execute(sql)
                return WriteResult(rowcount=cur.rowcount if cur.rowcount is not None else 0)

    async def run_script(self, sql: str) -> None:
        assert self._pool is not None, "connect() first"
        import sqlglot

        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                for stmt in sqlglot.parse(sql, dialect="mysql"):
                    if stmt is not None:
                        await cur.execute(stmt.sql(dialect="mysql"))

    async def list_tables(self) -> List[str]:
        res = await self.query(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema = DATABASE() ORDER BY table_name"
        )
        return [f"{r[0]}.{r[1]}" for r in res.rows]

    async def describe(self, table: str) -> List[Dict[str, str]]:
        parts = table.split(".")
        schema, name = (parts[0], parts[1]) if len(parts) == 2 else (self.default_schema, parts[0])
        res = await self.query(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            f"WHERE table_schema = '{schema}' AND table_name = '{name}' "
            "ORDER BY ordinal_position"
        )
        return [
            {"name": str(r[0]), "type": str(r[1]), "nullable": r[2] == "YES"}
            for r in res.rows
        ]


# ---------------------------------------------------------------------------
# Null executor — analysis / dry-run only, never touches a database
# ---------------------------------------------------------------------------


class NullExecutor(Executor):
    """An executor that refuses to run anything. Used by ``dbharness explain`` and
    other dry-run paths that only need the guard's dialect and schema."""

    def __init__(self, dialect: str = "postgres", default_schema: str = "public"):
        self.dialect = dialect
        self.default_schema = default_schema

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def query(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> QueryResult:
        raise RuntimeError("NullExecutor cannot execute statements")

    async def execute(self, sql: str, session: "Optional[Dict[str, str]]" = None) -> WriteResult:
        raise RuntimeError("NullExecutor cannot execute statements")

    async def list_tables(self) -> List[str]:
        return []

    async def describe(self, table: str) -> List[Dict[str, str]]:
        return []


def make_executor(backend: str, dsn: Optional[str] = None) -> Executor:
    backend = backend.lower()
    if backend == "sqlite":
        return SqliteExecutor(dsn or ":memory:")
    if backend in ("postgres", "postgresql"):
        if not dsn:
            raise ValueError("postgres backend requires a DSN (connection string)")
        return PostgresExecutor(dsn)
    if backend in ("mysql", "mariadb"):
        if not dsn:
            raise ValueError("mysql backend requires a DSN (connection string)")
        return MySQLExecutor(dsn)
    if backend == "null":
        return NullExecutor()
    raise ValueError(
        f"unknown backend {backend!r} (use 'sqlite', 'postgres', 'mysql', or 'null')")
