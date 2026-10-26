"""Assemble a :class:`Gate` from environment configuration.

Environment variables:

* ``DBHARNESS_POLICY``    — path to the policy YAML (default ``policies/example.yaml``).
* ``DBHARNESS_BACKEND``   — ``sqlite`` (default), ``postgres``, or ``mysql``.
* ``DBHARNESS_DSN``       — connection string (a file path for sqlite, default
                           ``:memory:``), OR a secret reference resolved via
                           :mod:`dbharness.secrets` (``env:PGDSN``,
                           ``file:/run/secrets/dsn``, or a custom provider).
* ``DBHARNESS_AUDIT_LOG`` — audit log path (default ``./dbharness-audit.jsonl``).
* ``DBHARNESS_API_KEY``   — the connecting agent's key; the server resolves it to
                           a principal at startup.
* ``DBHARNESS_SEED_SQL``  — optional path to a .sql file run once after connect
                           (handy for seeding a demo sqlite DB).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dbharness.audit import AuditLog
from dbharness.db import Executor, make_executor
from dbharness.gate import Gate
from dbharness.observability import Observer
from dbharness.pam import PamBroker
from dbharness.policy.loader import load_policy
from dbharness.secrets import resolve_secret
from dbharness.sql import SqlGuard


@dataclass
class Settings:
    policy_path: str
    backend: str
    dsn: str
    audit_path: str
    api_key: Optional[str]
    seed_sql: Optional[str]
    nl_translator: Optional[str] = None

    @classmethod
    def from_env(cls) -> "Settings":
        backend = os.environ.get("DBHARNESS_BACKEND", "sqlite").lower()
        default_dsn = ":memory:" if backend == "sqlite" else ""
        return cls(
            policy_path=os.environ.get("DBHARNESS_POLICY", "policies/example.yaml"),
            backend=backend,
            dsn=os.environ.get("DBHARNESS_DSN", default_dsn),
            audit_path=os.environ.get("DBHARNESS_AUDIT_LOG", "./dbharness-audit.jsonl"),
            api_key=os.environ.get("DBHARNESS_API_KEY"),
            seed_sql=os.environ.get("DBHARNESS_SEED_SQL"),
            nl_translator=os.environ.get("DBHARNESS_NL"),
        )


def build_gate(settings: Optional[Settings] = None,
               observer: Optional[Observer] = None) -> Gate:
    settings = settings or Settings.from_env()
    policy = load_policy(settings.policy_path)
    # The DSN may be a secret reference (env:/file:/vault:...) — resolve it so
    # the real connection string never has to live in the config or process args.
    dsn = resolve_secret(settings.dsn) if settings.dsn else settings.dsn
    executor: Executor = make_executor(settings.backend, dsn)
    audit = AuditLog(settings.audit_path)
    guard = SqlGuard(dialect=executor.dialect, default_schema=executor.default_schema)
    translator = _make_translator(settings.nl_translator)
    return Gate(policy=policy, executor=executor, audit=audit,
                pam=PamBroker(), guard=guard, observer=observer, translator=translator)


def _make_translator(name: Optional[str]):
    """Choose the natural-language translator (default: rule-based, offline)."""
    if name and name.lower() in ("llm", "claude", "anthropic"):
        from dbharness.nl import LLMTranslator
        return LLMTranslator()
    return None  # Gate falls back to the deterministic RuleBasedTranslator
