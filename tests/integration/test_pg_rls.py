"""Row-Level-Security defense-in-depth tests (live PostgreSQL).

These prove the SECOND enforcement layer: with the schema under RLS and the gate
connected as the least-privilege `dbharness_agent` role, PostgreSQL refuses
cross-tenant access *even for a raw, unfiltered statement* — i.e. even if a gate
bug let one through. The tenant is carried by the transaction-local
`dbharness.tenant_id` GUC the gate sets from the principal's context.
"""

import os
from urllib.parse import urlparse, urlunparse

import pytest

from dbharness.audit import AuditLog
from dbharness.db import PostgresExecutor
from dbharness.gate import Gate
from dbharness.policy.loader import load_policy

pytestmark = pytest.mark.asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "policies", "example.yaml")
RLS_SQL = os.path.join(ROOT, "postgres", "rls.sql")


def _agent_dsn(base_dsn: str) -> str:
    """Rewrite a superuser DSN to connect as the restricted dbharness_agent role."""
    p = urlparse(base_dsn)
    netloc = f"dbharness_agent:agentpw@{p.hostname}:{p.port or 5432}"
    return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))


@pytest.fixture
async def rls_agent(pg_executor, tmp_path):
    """Seed + install RLS (as superuser), then hand back an executor connected as
    the least-privilege, RLS-subject role."""
    with open(RLS_SQL, encoding="utf-8") as fh:
        await pg_executor.run_script(fh.read())

    base = os.environ["DBHARNESS_TEST_PG_DSN"]
    agent = PostgresExecutor(_agent_dsn(base))
    await agent.connect()
    try:
        yield agent
    finally:
        await agent.close()


ACME = {"dbharness.tenant_id": "acme"}
GLOBEX = {"dbharness.tenant_id": "globex"}


async def test_rls_blocks_cross_tenant_on_raw_read(rls_agent):
    # A RAW, unfiltered query (as if the gate were bypassed) still only returns
    # the tenant named by the session GUC.
    res = await rls_agent.query("SELECT id, tenant_id FROM tickets", session=ACME)
    assert {r[1] for r in res.rows} == {"acme"}
    assert 3 not in {r[0] for r in res.rows}  # globex ticket invisible


async def test_rls_scopes_to_the_other_tenant_too(rls_agent):
    res = await rls_agent.query("SELECT id, tenant_id FROM tickets", session=GLOBEX)
    assert {r[1] for r in res.rows} == {"globex"}
    assert {r[0] for r in res.rows} == {3}


async def test_rls_fails_closed_without_tenant_context(rls_agent):
    # No GUC set -> current_setting returns NULL -> zero rows. Fail closed.
    res = await rls_agent.query("SELECT id FROM tickets", session=None)
    assert res.rows == []


async def test_rls_with_check_blocks_forged_insert(rls_agent):
    # Even a raw INSERT cannot forge another tenant: the WITH CHECK clause rejects
    # a row whose tenant_id != the session GUC.
    with pytest.raises(Exception):
        await rls_agent.execute(
            "INSERT INTO tickets (id, tenant_id, subject) VALUES (900, 'globex', 'x')",
            session=ACME,
        )


async def test_rls_with_check_allows_own_tenant_insert(rls_agent):
    res = await rls_agent.execute(
        "INSERT INTO tickets (id, tenant_id, subject) VALUES (901, 'acme', 'ok')",
        session=ACME,
    )
    assert res.rowcount == 1


async def test_gate_over_rls_role_still_functions(rls_agent, tmp_path):
    # The gate, connected through the restricted RLS role, works normally: the
    # principal's tenant flows into the GUC and both layers agree.
    gate = Gate(
        policy=load_policy(POLICY),
        executor=rls_agent,
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
    )
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(support, "SELECT id, tenant_id FROM tickets", "read")
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} == {"acme"}
