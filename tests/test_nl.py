"""Tests for the natural-language layer (RuleBasedTranslator + gate flow).

Security stance: natural language is untrusted input. These tests confirm that
whatever the words say, the gate still enforces tenant scoping, column redaction,
and the scoping-column rule — and that writes are previewed, not executed blind.
"""

import pytest

from dbharness.nl import NLError, RuleBasedTranslator

TICKETS = ["id", "tenant_id", "subject", "status", "priority", "customer_id"]
SCHEMA = {
    "public.tickets": TICKETS,
    "public.customers": ["id", "tenant_id", "name", "email", "plan"],  # no ssn
}
CTX = {"tenant_id": "acme"}
tr = RuleBasedTranslator()


def _t(text):
    return tr.translate(text, schema=SCHEMA, context=CTX)


# -- translator units --------------------------------------------------------


def test_find_defaults_to_allowed_columns():
    r = _t("show all tickets")
    assert r.kind == "structured" and r.op == "find" and r.mode == "read"
    assert r.kwargs["columns"] == TICKETS  # explicit columns, never SELECT *


def test_count_emits_gated_sql():
    r = _t("how many customers")
    assert r.kind == "sql" and r.mode == "read" and "COUNT(*)" in r.sql


def test_find_with_condition():
    r = _t("find tickets where status is open")
    assert r.kwargs["filters"] == [{"column": "status", "op": "eq", "value": "open"}]


def test_find_operators_and_limit():
    r = _t("show tickets where id greater than 1 limit 5")
    assert {"column": "id", "op": "gt", "value": 1} in r.kwargs["filters"]
    assert r.kwargs["limit"] == 5


def test_update_parses_assignment_and_filter():
    r = _t("set status to closed on tickets where id is 1")
    assert r.op == "update" and r.mode == "write"
    assert r.kwargs["values"] == {"status": "closed"}
    assert r.kwargs["filters"] == [{"column": "id", "op": "eq", "value": 1}]


def test_delete_parses():
    r = _t("delete tickets where id is 1")
    assert r.op == "delete" and r.mode == "write"
    assert r.kwargs["filters"] == [{"column": "id", "op": "eq", "value": 1}]


def test_unknown_table_raises():
    with pytest.raises(NLError):
        _t("show all invoices")


def test_gibberish_raises():
    with pytest.raises(NLError):
        _t("please do the needful")


# -- through the gate: enforcement still applies -----------------------------


@pytest.mark.asyncio
async def test_nl_read_is_tenant_scoped(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "show all tickets")
    assert res.status == "ok"
    assert {r[1] for r in res.data["rows"]} == {"acme"}
    assert "interpretation" in res.data


@pytest.mark.asyncio
async def test_nl_count(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "how many tickets are there")
    assert res.status == "ok"
    assert res.data["rows"][0][0] == 2  # acme only


@pytest.mark.asyncio
async def test_nl_list_customers_hides_ssn(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "list customers")
    assert res.status == "ok"
    assert "ssn" not in [c.lower() for c in res.data["columns"]]
    assert {r[1] for r in res.data["rows"]} == {"acme"}


@pytest.mark.asyncio
async def test_nl_filtered_read(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "find tickets where priority is high")
    assert res.status == "ok"
    assert all(r[4] == "high" for r in res.data["rows"])


@pytest.mark.asyncio
async def test_nl_cannot_name_unreadable_table(gate):
    # invoices isn't readable by support, so it's not in the schema the
    # translator sees — the request can't even be formed.
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "show all invoices")
    assert res.status == "error"


# -- natural-language writes: preview, confirm, and enforcement --------------


@pytest.mark.asyncio
async def test_nl_write_previews_then_confirms(gate):
    support = gate.authenticate("support-dev-key")
    preview = await gate.run_nl(support, "set status to closed on tickets where id is 1")
    assert preview.status == "needs_confirmation"
    assert preview.data["preview"]["allowed"] is True
    # nothing happened yet
    still = await gate.run_nl(support, "show tickets where id is 1")
    assert still.data["rows"][0][3] == "open"
    # confirm -> executes, still tenant-scoped by the gate
    done = await gate.run_nl(support, "set status to closed on tickets where id is 1",
                             confirm=True)
    assert done.status == "ok"
    assert "tenant_id = 'acme'" in done.effective_sql


@pytest.mark.asyncio
async def test_nl_write_cannot_forge_tenant(gate):
    # Even phrased in English, moving a row to another tenant is blocked.
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "set tenant_id to globex on tickets where id is 1")
    assert res.status in ("denied", "error")


@pytest.mark.asyncio
async def test_nl_delete_without_grant_denied(gate):
    # support has no delete grant; the preview should surface that as denied.
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "delete tickets where id is 1")
    assert res.status in ("denied", "error")


# -- "<table> N" resolves to id = N (natural way to name one row) -------------


def test_find_table_number_is_id():
    r = _t("show ticket 1")
    assert r.op == "find"
    assert r.kwargs["filters"] == [{"column": "id", "op": "eq", "value": 1}]


def test_update_table_number_is_id():
    r = _t("set status to closed on ticket 1")
    assert r.op == "update" and r.kwargs["values"] == {"status": "closed"}
    assert r.kwargs["filters"] == [{"column": "id", "op": "eq", "value": 1}]


def test_delete_table_number_is_id():
    r = _t("delete ticket 1")
    assert r.kwargs["filters"] == [{"column": "id", "op": "eq", "value": 1}]
    assert r.kwargs["all"] is False


def test_limit_before_table_is_not_id():
    r = _t("show top 5 tickets")  # number before table -> limit, not id
    assert r.kwargs.get("limit") == 5
    assert "filters" not in r.kwargs


@pytest.mark.asyncio
async def test_nl_show_ticket_1_returns_one_row(gate):
    support = gate.authenticate("support-dev-key")
    res = await gate.run_nl(support, "show ticket 1")
    assert res.status == "ok"
    assert [row[0] for row in res.data["rows"]] == [1]
