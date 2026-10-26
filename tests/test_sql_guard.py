"""Unit tests for the SQL guard: parsing, classification, and rewriting."""

import pytest

from dbharness.policy.models import Action
from dbharness.sql import Risk, SqlGuard, SqlGuardError

guard = SqlGuard(dialect="sqlite")


def test_rejects_multiple_statements():
    with pytest.raises(SqlGuardError):
        guard.analyze("SELECT 1; DROP TABLE tickets")


def test_rejects_ddl():
    with pytest.raises(SqlGuardError):
        guard.analyze("DROP TABLE tickets")
    with pytest.raises(SqlGuardError):
        guard.analyze("CREATE TABLE x (id int)")


def test_action_and_table_extraction():
    _, a = guard.analyze("SELECT id FROM tickets WHERE id = 1")
    assert a.action is Action.SELECT
    assert a.tables == ["public.tickets"]
    assert a.has_where is True


def test_unfiltered_write_is_high_risk():
    _, a = guard.analyze("DELETE FROM tickets")
    assert a.action is Action.DELETE
    assert a.has_where is False
    assert a.risk is Risk.HIGH


def test_star_table_detection():
    _, a = guard.analyze("SELECT * FROM customers")
    assert a.star_tables == {"public.customers"}


def test_row_filter_injection_single_table():
    root, _ = guard.analyze("SELECT id FROM tickets WHERE id = 1")
    out = guard.rewrite(root, {"public.tickets": "tenant_id = 'acme'"}, set(), set())
    assert "tenant_id = 'acme'" in out
    assert "id = 1" in out


def test_wildcard_blocked_when_column_redacted():
    root, a = guard.analyze("SELECT * FROM customers")
    with pytest.raises(SqlGuardError):
        guard.rewrite(root, {}, {"public.customers.ssn"}, a.star_tables)
