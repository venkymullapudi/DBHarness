"""Live-PostgreSQL integration tests.

The unit suite proves the enforcement logic against SQLite. This suite proves the
same guarantees hold against a *real* PostgreSQL server — where the rewrites
(derived-table wrapping, qualified WHERE injection, RETURNING handling) meet the
actual query planner, and where Postgres-only threats (data-modifying CTEs,
`pg_read_file`) are genuinely executable.

Run via ``scripts/run_pg_integration.sh`` (Dockerized Postgres) or point
``DBHARNESS_TEST_PG_DSN`` at any Postgres and run ``pytest tests/integration``.
"""

import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Behaviour: the gate works correctly against real Postgres
# ---------------------------------------------------------------------------


async def test_row_filter_scopes_reads(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(support, "SELECT id, tenant_id FROM tickets", "read")
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} == {"acme"}


async def test_scoped_update_executes_and_counts(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support, "UPDATE tickets SET status='closed' WHERE id=1", "write")
    assert res.status == "ok"
    assert res.data["rows_affected"] == 1


async def test_approval_flow_end_to_end(pg_gate):
    billing = pg_gate.authenticate("billing-dev-key")
    admin = pg_gate.authenticate("admin-dev-key")
    pending = await pg_gate.handle_sql(
        billing, "UPDATE customers SET plan='enterprise' WHERE id=1", "write")
    assert pending.status == "pending_approval"
    pg_gate.pam.decide(pending.approval_id, approve=True, approver=admin.id)
    done = await pg_gate.run_approved(billing, pending.approval_id)
    assert done.status == "ok"
    assert done.data["rows_affected"] == 1


async def test_insert_auto_scopes_tenant(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (id, ticket_id, author, body) "
        "VALUES (100, 1, 'ada', 'hi')",
        "write",
    )
    assert res.status == "ok"
    # Confirm the row really landed with the principal's tenant.
    check = await pg_gate.handle_sql(
        pg_gate.authenticate("admin-dev-key"),
        "SELECT tenant_id FROM ticket_comments WHERE id=100", "read")
    assert check.data["rows"][0][0] == "acme"


# ---------------------------------------------------------------------------
# Tenant isolation must hold against the real planner
# ---------------------------------------------------------------------------


async def test_subquery_cannot_escape_tenant(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "SELECT id FROM tickets WHERE id IN (SELECT id FROM tickets)",
        "read",
    )
    assert res.status == "ok"
    assert {r[0] for r in res.data["rows"]} <= {1, 2}


async def test_cte_read_is_tenant_filtered(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "WITH t AS (SELECT id, tenant_id FROM tickets) SELECT * FROM t",
        "read",
    )
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} <= {"acme"}


async def test_join_cannot_leak_other_tenant(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "SELECT t.id, c.name FROM tickets t JOIN customers c ON t.customer_id = c.id",
        "read",
    )
    assert res.status == "ok"
    assert "Grace Hopper" not in {r[1] for r in res.data["rows"]}


async def test_or_precedence_cannot_bypass_filter(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support, "UPDATE tickets SET status='hacked' WHERE id=3 OR id=1", "write")
    assert res.status == "ok"
    assert res.data["rows_affected"] == 1  # only the acme row
    check = await pg_gate.handle_sql(
        pg_gate.authenticate("admin-dev-key"),
        "SELECT status FROM tickets WHERE id=3", "read")
    assert check.data["rows"][0][0] != "hacked"


async def test_cross_tenant_insert_blocked(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (id, tenant_id, ticket_id, author, body) "
        "VALUES (101, 'globex', 3, 'x', 'pwned')",
        "write",
    )
    assert res.status in ("denied", "error")


# ---------------------------------------------------------------------------
# Postgres-specific threats that SQLite cannot even demonstrate
# ---------------------------------------------------------------------------


async def test_data_modifying_cte_is_a_real_threat_and_is_blocked(pg_executor, pg_gate):
    """A data-modifying CTE genuinely writes on Postgres — prove it, then prove
    the gate blocks the same statement so it never reaches the database."""
    attack = "WITH x AS (DELETE FROM tickets WHERE id=2 RETURNING id) SELECT * FROM x"

    # 1. Unguarded, Postgres executes the DELETE inside the "SELECT".
    await pg_executor.run_script(attack)
    gone = await pg_executor.query("SELECT count(*) FROM tickets WHERE id=2")
    assert gone.rows[0][0] == 0  # the raw statement really deleted the row

    # 2. Through the gate (read channel), the same statement is refused outright.
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(support, attack, "read")
    assert res.status in ("denied", "error")


async def test_pg_read_file_blocked(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support, "SELECT pg_read_file('/etc/hostname') FROM tickets", "read")
    assert res.status in ("denied", "error")


async def test_returning_cannot_leak_redacted_column(pg_gate):
    billing = pg_gate.authenticate("billing-dev-key")
    res = await pg_gate.handle_sql(
        billing, "UPDATE customers SET plan='x' WHERE id=1 RETURNING ssn", "write")
    assert res.status == "denied"


async def test_ssn_scalar_subquery_leak_blocked(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(
        support,
        "SELECT id, (SELECT ssn FROM customers LIMIT 1) AS leaked FROM tickets",
        "read",
    )
    assert res.status == "denied"


async def test_wildcard_over_redacted_table_blocked(pg_gate):
    support = pg_gate.authenticate("support-dev-key")
    res = await pg_gate.handle_sql(support, "SELECT * FROM customers", "read")
    assert res.status == "denied"
