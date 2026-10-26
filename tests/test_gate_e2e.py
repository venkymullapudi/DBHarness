"""End-to-end tests through the full Gate pipeline against a live SQLite DB."""

import pytest


async def _auth(gate):
    return (
        gate.authenticate("support-dev-key"),
        gate.authenticate("billing-dev-key"),
        gate.authenticate("admin-dev-key"),
    )


@pytest.mark.asyncio
async def test_row_scoping_hides_other_tenants(gate):
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(support, "SELECT id, tenant_id FROM tickets", "read")
    assert res.status == "ok"
    tenants = {row[1] for row in res.data["rows"]}
    assert tenants == {"acme"}  # globex row is filtered out


@pytest.mark.asyncio
async def test_redacted_column_denied(gate):
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(support, "SELECT id, ssn FROM customers", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_wildcard_over_redacted_table_blocked(gate):
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(support, "SELECT * FROM customers", "read")
    assert res.status == "denied"


@pytest.mark.asyncio
async def test_read_channel_rejects_write(gate):
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(support, "DELETE FROM tickets WHERE id=1", "read")
    assert res.status == "denied"
    assert "write channel" in res.reason


@pytest.mark.asyncio
async def test_scoped_update_executes(gate):
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(
        support, "UPDATE tickets SET status='closed' WHERE id=1", "write")
    assert res.status == "ok"
    assert "tenant_id = 'acme'" in res.effective_sql


@pytest.mark.asyncio
async def test_cross_tenant_update_touches_no_rows(gate):
    # ticket 3 belongs to globex; the injected filter means 0 rows affected.
    support, _, _ = await _auth(gate)
    res = await gate.handle_sql(
        support, "UPDATE tickets SET status='closed' WHERE id=3", "write")
    assert res.status == "ok"
    assert res.data["rows_affected"] == 0


@pytest.mark.asyncio
async def test_unfiltered_delete_requires_approval_even_for_admin(gate):
    _, _, admin = await _auth(gate)
    res = await gate.handle_sql(admin, "DELETE FROM tickets", "write")
    assert res.status == "pending_approval"  # hard safety net for unfiltered mutation


@pytest.mark.asyncio
async def test_approval_flow_binds_exact_statement(gate):
    support, billing, admin = await _auth(gate)
    pending = await gate.handle_sql(
        billing, "UPDATE customers SET plan='enterprise' WHERE id=1", "write")
    assert pending.status == "pending_approval"

    # Cannot run before approval.
    blocked = await gate.run_approved(billing, pending.approval_id)
    assert blocked.status == "error"

    # A different principal cannot consume it.
    gate.pam.decide(pending.approval_id, approve=True, approver=admin.id)
    wrong = await gate.run_approved(support, pending.approval_id)
    assert wrong.status == "error"

    ok = await gate.run_approved(billing, pending.approval_id)
    assert ok.status == "ok"

    # Cannot be replayed.
    replay = await gate.run_approved(billing, pending.approval_id)
    assert replay.status == "error"


@pytest.mark.asyncio
async def test_bad_api_key_rejected(gate):
    from dbharness.gate import AuthError
    with pytest.raises(AuthError):
        gate.authenticate("not-a-real-key")
