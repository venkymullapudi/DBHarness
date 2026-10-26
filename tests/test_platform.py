"""Tests for the platform capabilities: secrets, observability, audit sinks,
PAM store seam, dry-run explain, and the CLI."""

import os

import pytest

from dbharness.audit import AuditLog, FileAuditSink, NullAuditSink
from dbharness.observability import InMemoryMetrics, NullObserver
from dbharness.secrets import SecretError, register_provider, resolve_secret

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(ROOT, "policies", "example.yaml")


# -- secrets -----------------------------------------------------------------


def test_secret_plain_and_literal():
    assert resolve_secret("plain:hunter2") == "hunter2"
    assert resolve_secret("just-a-literal") == "just-a-literal"


def test_secret_dsn_uri_is_passthrough():
    # A full URI must not be mistaken for a scheme reference.
    dsn = "postgresql://u:p@host:5432/db"
    assert resolve_secret(dsn) == dsn


def test_secret_env(monkeypatch):
    monkeypatch.setenv("DBHARNESS_TEST_SECRET", "s3cr3t")
    assert resolve_secret("env:DBHARNESS_TEST_SECRET") == "s3cr3t"


def test_secret_env_missing():
    with pytest.raises(SecretError):
        resolve_secret("env:definitely_not_set_12345")


def test_secret_file(tmp_path):
    p = tmp_path / "dsn.txt"
    p.write_text("  postgresql://x  \n")
    assert resolve_secret(f"file:{p}") == "postgresql://x"


def test_custom_provider():
    register_provider("test-vault", lambda loc: f"resolved::{loc}")
    assert resolve_secret("test-vault:secret/dsn") == "resolved::secret/dsn"


# -- audit sinks -------------------------------------------------------------


def test_null_audit_sink_discards():
    log = AuditLog(sink=NullAuditSink())
    log.record(log.new_record("p", "select", "executed"))
    assert log.tail(10) == []


def test_file_audit_sink_roundtrip(tmp_path):
    log = AuditLog(sink=FileAuditSink(str(tmp_path / "a.jsonl")))
    log.record(log.new_record("p", "select", "executed", rows=3))
    tail = log.tail(10)
    assert tail[-1]["principal_id"] == "p" and tail[-1]["rows"] == 3


def test_audit_requires_path_or_sink():
    with pytest.raises(ValueError):
        AuditLog()


# -- observability -----------------------------------------------------------


def test_null_observer_is_noop():
    NullObserver().event("request", outcome="executed")  # must not raise


@pytest.mark.asyncio
async def test_metrics_count_gate_outcomes(gate):
    metrics = InMemoryMetrics()
    gate.observer = metrics
    support = gate.authenticate("support-dev-key")
    await gate.handle_sql(support, "SELECT id FROM tickets", "read")          # executed
    await gate.handle_sql(support, "SELECT ssn FROM customers", "read")       # denied
    await gate.handle_sql(support, "DELETE FROM tickets WHERE id=1", "write") # denied (no grant)
    snap = metrics.snapshot()
    assert snap["request.executed"] == 1
    assert snap["request.denied"] == 2
    assert snap["request"] == 3


# -- PAM store seam ----------------------------------------------------------


def test_pam_uses_injected_store():
    from dbharness.pam import InMemoryPamStore, PamBroker

    store = InMemoryPamStore()
    broker = PamBroker(store=store)
    approval = broker.create_approval("p", "update", "high", "raw", "eff", "why")
    # The broker's state lives in the injected store.
    assert store.get_approval(approval.id) is approval
    broker.elevate("p", "admin", granted_by="op", minutes=5)
    assert "admin" in broker.active_roles("p")


# -- dry-run explain ---------------------------------------------------------


@pytest.mark.asyncio
async def test_explain_shows_injected_filter(gate):
    support = gate.authenticate("support-dev-key")
    out = gate.explain(support, "SELECT id, subject FROM tickets", "read")
    assert out["allowed"] is True
    assert "public.tickets" in out["row_filters"]
    assert "tenant_id" in out["effective_sql"]


@pytest.mark.asyncio
async def test_explain_denies_redacted_column(gate):
    support = gate.authenticate("support-dev-key")
    out = gate.explain(support, "SELECT ssn FROM customers", "read")
    assert out["allowed"] is False
    assert out["stage"] == "authorize"


@pytest.mark.asyncio
async def test_explain_flags_required_approval(gate):
    billing = gate.authenticate("billing-dev-key")
    out = gate.explain(billing, "UPDATE customers SET plan='x' WHERE id=1", "write")
    assert out["allowed"] is True
    assert out["requires_approval"] is True


def test_explain_does_not_touch_db():
    # explain must work with a NullExecutor that raises on any query/execute.
    from dbharness.db import NullExecutor
    from dbharness.gate import Gate
    from dbharness.policy.loader import load_policy

    g = Gate(policy=load_policy(POLICY),
             executor=NullExecutor(dialect="postgres"),
             audit=AuditLog(sink=NullAuditSink()))
    principal = g.policy.principals["support-bot"]
    out = g.explain(principal, "SELECT id FROM tickets", "read")
    assert out["allowed"] is True


# -- CLI ---------------------------------------------------------------------


def test_cli_policy_validate_ok(capsys):
    from dbharness.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["policy", "validate", POLICY])
    assert exc.value.code == 0
    assert "OK" in capsys.readouterr().out


def test_cli_policy_validate_bad(tmp_path, capsys):
    from dbharness.cli import main

    bad = tmp_path / "bad.yaml"
    bad.write_text("principals:\n  - id: x\n    roles: [nope]\n")  # unknown role, no key
    with pytest.raises(SystemExit) as exc:
        main(["policy", "validate", str(bad)])
    assert exc.value.code == 1


def test_cli_explain_denied_exit_code(capsys):
    from dbharness.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["explain", "--policy", POLICY, "--principal", "support-bot",
              "--sql", "SELECT ssn FROM customers", "--dialect", "sqlite"])
    assert exc.value.code == 1  # denied -> non-zero
    assert '"allowed": false' in capsys.readouterr().out


def test_cli_explain_allowed(capsys):
    from dbharness.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["explain", "--policy", POLICY, "--principal", "support-bot",
              "--sql", "SELECT id FROM tickets", "--dialect", "sqlite"])
    assert exc.value.code == 0
    assert '"allowed": true' in capsys.readouterr().out


# -- MySQL adapter (construction + dialect; live integration needs a server) --


def test_mysql_executor_parses_dsn_and_schema():
    from dbharness.db import MySQLExecutor, make_executor

    ex = MySQLExecutor("mysql://user:pw@dbhost:3306/appdb")
    assert ex.dialect == "mysql"
    assert ex.default_schema == "appdb"      # MySQL schema == database name
    assert isinstance(make_executor("mysql", "mysql://u@h/appdb"), MySQLExecutor)


def test_mysql_dialect_guard_rewrites():
    from dbharness.sql import SqlGuard

    g = SqlGuard(dialect="mysql", default_schema="appdb")
    root, analyzed = g.analyze("SELECT id FROM tickets WHERE id = 1")
    assert analyzed.tables == ["appdb.tickets"]
    out = g.rewrite(root, {"appdb.tickets": "tenant_id = 'acme'"}, set(), set())
    assert "tenant_id = 'acme'" in out


def test_null_backend_factory():
    from dbharness.db import NullExecutor, make_executor

    assert isinstance(make_executor("null"), NullExecutor)
