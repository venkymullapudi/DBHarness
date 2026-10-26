import os

import pytest

from dbharness.audit import AuditLog
from dbharness.db import SqliteExecutor
from dbharness.gate import Gate
from dbharness.policy.loader import load_policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(ROOT, "policies", "example.yaml")
SEED = os.path.join(ROOT, "examples", "seed.sql")


@pytest.fixture
async def gate(tmp_path):
    executor = SqliteExecutor(":memory:")
    await executor.connect()
    with open(SEED, encoding="utf-8") as fh:
        await executor.run_script(fh.read())
    g = Gate(
        policy=load_policy(POLICY),
        executor=executor,
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
    )
    yield g
    await executor.close()
