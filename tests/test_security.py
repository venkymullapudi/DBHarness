"""Adversarial security tests — the attacks the gate MUST defeat.

Every test here encodes a way a malicious or prompt-injected agent might try to
exceed its grant. The expected outcome is always the *secure* one: denied,
blocked, or filtered. If any of these fail, there is a real bypass.

The gate fixture authenticates as `support-bot` (tenant=acme, read tickets/
comments, read customers minus ssn, insert comments, update tickets — all
tenant-scoped) unless a test says otherwise.
"""

import pytest

from dbharness.sql import SqlGuard, SqlGuardError

# A guard configured like the Postgres deployment (the real target). Used for
# statement-shape attacks that don't need a live DB.
pg = SqlGuard(dialect="postgres")


# ---------------------------------------------------------------------------
# Statement-shape attacks (guard level)
# ---------------------------------------------------------------------------


def test_stacked_statements_blocked():
    with pytest.raises(SqlGuardError):
        pg.analyze("SELECT id FROM tickets; DROP TABLE tickets")


def test_ddl_blocked():
    for sql in [
        "DROP TABLE customers",
        "ALTER TABLE customers ADD COLUMN x int",
        "CREATE TABLE evil (id int)",
        "TRUNCATE customers",
    ]:
        with pytest.raises(SqlGuardError):
            pg.analyze(sql)


def test_data_modifying_cte_blocked():
    # Postgres executes DML inside a WITH — a SELECT-looking statement that writes.
    attacks = [
        "WITH x AS (DELETE FROM tickets RETURNING *) SELECT * FROM x",
        "WITH x AS (UPDATE tickets SET status='closed' RETURNING *) SELECT * FROM x",
        "WITH x AS (INSERT INTO tickets(id) VALUES (99) RETURNING *) SELECT * FROM x",
    ]
    for sql in attacks:
        with pytest.raises(SqlGuardError):
            pg.analyze(sql)


def test_select_into_blocked():
    with pytest.raises(SqlGuardError):
        pg.analyze("SELECT * INTO evil FROM customers")


def test_dangerous_functions_blocked():
    attacks = [
        "SELECT pg_read_file('/etc/passwd') FROM tickets",
        "SELECT pg_ls_dir('/') FROM tickets",
        "SELECT lo_import('/etc/passwd') FROM tickets",
        "SELECT dblink('host=evil', 'select 1') FROM tickets",
        "SELECT pg_sleep(10) FROM tickets",
    ]
    for sql in attacks:
        with pytest.raises(SqlGuardError):
            pg.analyze(sql)


def test_sqlite_load_extension_blocked():
    g = SqlGuard(dialect="sqlite")
    with pytest.raises(SqlGuardError):
        g.analyze("SELECT load_extension('evil.so') FROM tickets")


# ---------------------------------------------------------------------------
# Row-scoping (tenant isolation) attacks — through the full gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subquery_cannot_escape_tenant(gate):
    support = gate.authenticate("support-dev-key")
    # A subquery over tickets must still be tenant-filtered.
    res = await gate.handle_sql(
        support,
        "SELECT id FROM tickets WHERE id IN (SELECT id FROM tickets)",
        "read",
    )
    assert res.status == "ok"
    ids = {r[0] for r in res.data["rows"]}
    assert ids <= {1, 2}  # never ticket 3 (globex)


@pytest.mark.asyncio
async def test_cte_read_is_tenant_filtered(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "WITH t AS (SELECT id, tenant_id FROM tickets) SELECT * FROM t",
        "read",
    )
    assert res.status == "ok"
    tenants = {r[1] for r in res.data["rows"]}
    assert tenants <= {"acme"}


@pytest.mark.asyncio
async def test_join_cannot_leak_other_tenant(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT t.id, c.name FROM tickets t JOIN customers c ON t.customer_id = c.id",
        "read",
    )
    assert res.status == "ok"
    # Only acme customers (1,2) can appear; globex customer 3 must be invisible.
    names = {r[1] for r in res.data["rows"]}
    assert "Grace Hopper" not in names


@pytest.mark.asyncio
async def test_update_cannot_move_row_across_tenant(gate):
    # Support may update tickets, but must not repartition a row into another tenant
    # by SETting the scoping column.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "UPDATE tickets SET tenant_id='globex' WHERE id=1", "write")
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_update_only_hits_own_tenant(gate):
    support = gate.authenticate("support-dev-key")
    # Try to close the globex ticket (id 3). Filter must make it affect 0 rows.
    res = await gate.handle_sql(
        support, "UPDATE tickets SET status='closed' WHERE id=3", "write")
    assert res.status == "ok"
    assert res.data["rows_affected"] == 0


# ---------------------------------------------------------------------------
# Column redaction attacks — through the full gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssn_via_alias_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(support, "SELECT ssn AS x FROM customers", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_ssn_via_expression_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "SELECT ssn || 'z' FROM customers", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_ssn_via_scalar_subquery_blocked(gate):
    # The dangerous one: ssn hidden in a subquery while the outer FROM is a
    # different table, so a naive analyzer never qualifies it.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT id, (SELECT ssn FROM customers LIMIT 1) AS leaked FROM tickets",
        "read",
    )
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_ssn_via_where_subquery_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT id FROM tickets WHERE 'x' IN (SELECT ssn FROM customers)",
        "read",
    )
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_star_via_alias_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(support, "SELECT c.* FROM customers c", "read")
    assert res.status == "denied"


# ---------------------------------------------------------------------------
# Cross-tenant / privilege attacks on writes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_cannot_forge_other_tenant(gate):
    # Support may insert comments, but not for the globex tenant.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (tenant_id, ticket_id, author, body) "
        "VALUES ('globex', 3, 'x', 'pwned')",
        "write",
    )
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_insert_auto_scopes_tenant(gate):
    # Omitting tenant_id should be auto-filled with the principal's tenant, not
    # left to the agent.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (ticket_id, author, body) "
        "VALUES (1, 'ada', 'hello')",
        "write",
    )
    assert res.status == "ok"
    assert "acme" in res.effective_sql


@pytest.mark.asyncio
async def test_read_channel_rejects_data_modifying_cte(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "WITH x AS (DELETE FROM tickets RETURNING id) SELECT * FROM x",
        "read",
    )
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_ungranted_table_in_join_denied(gate):
    # invoices is not granted to support; joining it in must deny the whole read.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT t.id, i.amount_cents FROM tickets t JOIN invoices i "
        "ON i.customer_id = t.customer_id",
        "read",
    )
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_ungranted_table_in_subquery_denied(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT id FROM tickets WHERE customer_id IN (SELECT customer_id FROM invoices)",
        "read",
    )
    assert res.status == "denied"


# ---------------------------------------------------------------------------
# Second wave: precedence, set-ops, RETURNING, obfuscation, multi-row
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_or_in_where_cannot_bypass_tenant_filter(gate):
    # The injected tenant filter must bind with correct precedence even when the
    # agent's WHERE contains an OR that references another tenant's row.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "UPDATE tickets SET status='hacked' WHERE id=3 OR id=1", "write")
    assert res.status == "ok"
    # Only the acme row (id=1) may change; the globex row (id=3) must be untouched.
    assert res.data["rows_affected"] == 1
    # Verify directly that ticket 3 was not modified.
    check = await gate.handle_sql(
        gate.authenticate("admin-dev-key"),
        "SELECT status FROM tickets WHERE id=3", "read")
    assert check.data["rows"][0][0] != "hacked"


@pytest.mark.asyncio
async def test_delete_or_precedence_scoped(gate):
    admin = gate.authenticate("admin-dev-key")
    # Give support a delete grant via elevation is overkill; test with admin-scoped?
    # Instead confirm the SQL rewrite parenthesizes for support update above; here
    # ensure a support DELETE stays denied (no grant) regardless of OR tricks.
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "DELETE FROM tickets WHERE id=3 OR 1=1", "write")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_union_cannot_leak_redacted_column(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT id FROM tickets UNION SELECT ssn FROM customers",
        "read",
    )
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_union_branch_is_tenant_filtered(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT id, tenant_id FROM tickets UNION SELECT id, tenant_id FROM tickets",
        "read",
    )
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} <= {"acme"}


@pytest.mark.asyncio
async def test_union_with_ungranted_table_denied(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "SELECT id FROM tickets UNION SELECT id FROM invoices", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_self_join_stays_tenant_scoped(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT a.id, b.id FROM tickets a JOIN tickets b ON a.id <> b.id",
        "read",
    )
    assert res.status == "ok"
    ids = {r[0] for r in res.data["rows"]} | {r[1] for r in res.data["rows"]}
    assert 3 not in ids  # globex ticket never appears on either side


@pytest.mark.asyncio
async def test_returning_cannot_leak_redacted_column(gate):
    billing = gate.authenticate("billing-dev-key")
    res = await gate.handle_sql(
        billing, "UPDATE customers SET plan='x' WHERE id=1 RETURNING ssn", "write")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_returning_star_over_redacted_table_blocked(gate):
    billing = gate.authenticate("billing-dev-key")
    res = await gate.handle_sql(
        billing, "UPDATE customers SET plan='x' WHERE id=1 RETURNING *", "write")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_order_by_redacted_column_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "SELECT id FROM customers ORDER BY ssn", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_aggregate_over_redacted_column_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "SELECT max(ssn) FROM customers", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_case_expression_leaking_redacted_column_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "SELECT CASE WHEN ssn IS NULL THEN 0 ELSE 1 END FROM customers",
        "read",
    )
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_uppercase_and_quoted_identifiers_still_redacted(gate):
    support = gate.authenticate("support-dev-key")
    for sql in ["SELECT SSN FROM CUSTOMERS", 'SELECT "ssn" FROM customers']:
        res = await gate.handle_sql(support, sql, "read")
        assert res.status == "denied", sql


@pytest.mark.asyncio
async def test_multi_row_insert_forging_tenant_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (tenant_id, ticket_id, author, body) VALUES "
        "('acme', 1, 'a', 'ok'), ('globex', 3, 'x', 'pwned')",
        "write",
    )
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_insert_without_column_list_into_scoped_table_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "INSERT INTO ticket_comments VALUES (99, 'globex', 3, 'x', 'pwned')",
        "write",
    )
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_insert_select_into_scoped_table_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support,
        "INSERT INTO ticket_comments (tenant_id, ticket_id, author, body) "
        "SELECT tenant_id, id, 'x', 'y' FROM tickets",
        "write",
    )
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_empty_statement_denied(gate):
    support = gate.authenticate("support-dev-key")
    for sql in ["", "   ", "-- just a comment"]:
        res = await gate.handle_sql(support, sql, "read")
        assert res.status in ("denied", "error"), sql


@pytest.mark.asyncio
async def test_explain_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(support, "EXPLAIN SELECT * FROM customers", "read")
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_cte_definition_redacted_column_blocked(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.handle_sql(
        support, "WITH x AS (SELECT ssn FROM customers) SELECT * FROM x", "read")
    assert res.status == "denied"
