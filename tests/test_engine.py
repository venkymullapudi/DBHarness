"""Unit tests for the RBAC decision engine (no database needed)."""

import os

from dbharness.policy.engine import PolicyEngine
from dbharness.policy.loader import load_policy
from dbharness.policy.models import Action

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
policy = load_policy(os.path.join(ROOT, "policies", "example.yaml"))
engine = PolicyEngine(policy)
support = policy.principals["support-bot"]
billing = policy.principals["billing-bot"]


def test_deny_by_default():
    # support has no grant on invoices
    d = engine.evaluate(support, Action.SELECT, ["public.invoices"])
    assert d.allowed is False


def test_row_filter_rendered_from_context():
    d = engine.evaluate(support, Action.SELECT, ["public.tickets"])
    assert d.allowed is True
    assert d.row_filters["public.tickets"] == "(tenant_id = 'acme')"


def test_denied_column_blocks_statement():
    d = engine.evaluate(
        support, Action.SELECT, ["public.customers"], ["public.customers.ssn"]
    )
    assert d.allowed is False
    assert "ssn" in d.reason


def test_no_delete_grant_for_support():
    d = engine.evaluate(support, Action.DELETE, ["public.tickets"])
    assert d.allowed is False


def test_billing_update_requires_approval():
    d = engine.evaluate(billing, Action.UPDATE, ["public.customers"])
    assert d.allowed is True
    assert d.require_approval is True


def test_elevation_grants_extra_role():
    # support cannot delete normally, but with an admin elevation it can.
    d = engine.evaluate(
        support, Action.DELETE, ["public.tickets"], extra_roles=["admin"]
    )
    assert d.allowed is True
