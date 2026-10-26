"""Tests for the structured query builder and its path through the gate."""

import pytest

from dbharness.querybuilder import QueryBuilderError, build, build_find


# -- compilation + safety (unit) ---------------------------------------------


def test_find_basic():
    sql, mode = build_find("tickets", filters={"status": "open"},
                           columns=["id", "subject"], limit=5, dialect="sqlite")
    assert mode == "read"
    assert "SELECT id, subject FROM tickets" in sql
    assert "status = 'open'" in sql and "LIMIT 5" in sql


def test_find_operators():
    sql, _ = build_find("customers", filters=[
        {"column": "plan", "op": "in", "value": ["pro", "free"]},
        {"column": "name", "op": "like", "value": "A%"},
    ], dialect="sqlite")
    assert "plan IN ('pro', 'free')" in sql
    assert "LIKE 'A%'" in sql


def test_insert_compiles():
    sql, mode = build("insert", dialect="sqlite", table="ticket_comments",
                      values={"ticket_id": 1, "author": "ada", "body": "hi"})
    assert mode == "write"
    assert sql.startswith("INSERT INTO ticket_comments")


def test_update_and_delete_require_filters():
    with pytest.raises(QueryBuilderError):
        build("update", table="tickets", values={"status": "x"})
    with pytest.raises(QueryBuilderError):
        build("delete", table="tickets")
    # explicit all=True is allowed to compile
    sql, _ = build("delete", dialect="sqlite", table="tickets", all=True)
    assert sql.strip() == "DELETE FROM tickets"


def test_identifier_injection_blocked():
    with pytest.raises(QueryBuilderError):
        build_find("tickets; DROP TABLE x")
    with pytest.raises(QueryBuilderError):
        build_find("tickets", filters={"id) OR 1=1 --": 1})


def test_unknown_op_and_bad_in():
    with pytest.raises(QueryBuilderError):
        build("frobnicate", table="tickets")
    with pytest.raises(QueryBuilderError):
        build_find("tickets", filters=[{"column": "id", "op": "in", "value": []}])


# -- through the gate: enforcement still applies (e2e) ------------------------


@pytest.mark.asyncio
async def test_structured_find_is_tenant_scoped(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "find", table="tickets",
                                    columns=["id", "tenant_id"])
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} == {"acme"}
    assert "tenant_id" in res.effective_sql  # gate injected the filter


@pytest.mark.asyncio
async def test_structured_find_redacted_column_denied(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "find", table="customers",
                                    columns=["id", "ssn"])
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_structured_insert_auto_scopes_tenant(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "insert", table="ticket_comments",
                                    values={"id": 50, "ticket_id": 1, "author": "ada", "body": "hi"})
    assert res.status == "ok"
    assert "acme" in res.effective_sql


@pytest.mark.asyncio
async def test_structured_insert_cannot_forge_tenant(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "insert", table="ticket_comments",
                                    values={"id": 51, "tenant_id": "globex",
                                            "ticket_id": 3, "author": "x", "body": "p"})
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_structured_update_scoped(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "update", table="tickets",
                                    values={"status": "closed"}, filters={"id": 1})
    assert res.status == "ok"
    assert "tenant_id = 'acme'" in res.effective_sql


@pytest.mark.asyncio
async def test_structured_privileged_update_needs_approval(gate):
    billing = gate.authenticate("billing-dev-key")
    res = await gate.run_structured(billing, "update", table="customers",
                                    values={"plan": "enterprise"}, filters={"id": 1})
    assert res.status == "pending_approval"


@pytest.mark.asyncio
async def test_structured_delete_without_grant_denied(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "delete", table="tickets", filters={"id": 1})
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_structured_unfiltered_update_rejected_by_builder(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_structured(support, "update", table="tickets",
                                    values={"status": "x"})  # no filters, no all
    assert res.status == "error"
    assert "without filters" in res.reason
