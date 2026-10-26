"""Fixtures for the live-PostgreSQL integration tests.

These tests only run when ``DBHARNESS_TEST_PG_DSN`` points at a reachable Postgres
(the Docker harness in ``scripts/run_pg_integration.sh`` sets it). When it is
unset — the normal unit-test run — every test here is skipped, so the default
``pytest`` invocation stays infra-free.

Each test gets a freshly-seeded database (the seed drops and recreates its
tables) so writes in one test never bleed into another.
"""

import os

import pytest

from dbharness.audit import AuditLog
from dbharness.db import PostgresExecutor
from dbharness.gate import Gate
from dbharness.policy.loader import load_policy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "policies", "example.yaml")
SEED = os.path.join(ROOT, "examples", "seed_pg.sql")

DSN = os.environ.get("DBHARNESS_TEST_PG_DSN")


@pytest.fixture
async def pg_executor():
    if not DSN:
        pytest.skip("DBHARNESS_TEST_PG_DSN not set")
    executor = PostgresExecutor(DSN)
    await executor.connect()
    with open(SEED, encoding="utf-8") as fh:
        await executor.run_script(fh.read())
    try:
        yield executor
    finally:
        await executor.close()


@pytest.fixture
async def pg_gate(pg_executor, tmp_path):
    yield Gate(
        policy=load_policy(POLICY),
        executor=pg_executor,
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
    )
