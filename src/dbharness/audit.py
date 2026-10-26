"""Immutable, append-only audit log.

Every request that reaches the gate produces exactly one audit record —
regardless of whether it was allowed, denied, held for approval, or errored.
This is the "session recording" for AI agents: given the log you can answer,
after the fact, *exactly* what each agent asked for, what the policy decided,
what actually ran against the database, and what it returned.

The MVP writes newline-delimited JSON to a local file, opened in append mode.
For production you would point this at an append-only store (an object-lock
bucket, a WORM table, or a log pipeline) so records cannot be altered after the
fact — the interface stays the same.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional  # noqa: F401


@dataclass
class AuditRecord:
    ts: str
    principal_id: str
    action: str  # select / insert / update / delete / <lifecycle event>
    outcome: str  # allowed | denied | pending_approval | error | executed
    raw_sql: str = ""
    effective_sql: str = ""
    tables: List[str] = field(default_factory=list)
    risk: str = ""
    reason: str = ""
    roles: List[str] = field(default_factory=list)
    rows: Optional[int] = None  # rows returned or affected
    approval_id: Optional[str] = None
    error: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


class AuditSink:
    """Where audit lines go. Swap this to point at an append-only/WORM store
    (object-lock bucket, WORM table, log pipeline) without touching the gate."""

    def write(self, line: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def tail(self, n: int) -> List[Dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError


class FileAuditSink(AuditSink):
    """Append newline-delimited JSON to a local file (thread-safe)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def write(self, line: str) -> None:
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        return [json.loads(l) for l in (s.strip() for s in lines[-n:]) if l]


class NullAuditSink(AuditSink):
    """Discard everything — for tests or explicitly-audit-disabled deployments."""

    def write(self, line: str) -> None:
        pass

    def tail(self, n: int) -> List[Dict[str, Any]]:
        return []


class AuditLog:
    """The audit facade the gate holds. Serializes records to its sink.

    Backwards compatible: ``AuditLog("path.jsonl")`` still writes to a file. Pass
    ``sink=`` to use any :class:`AuditSink` (e.g. a custom WORM sink).
    """

    def __init__(self, path: "Optional[str]" = None, sink: "Optional[AuditSink]" = None):
        if sink is None:
            if path is None:
                raise ValueError("AuditLog needs a path or a sink")
            sink = FileAuditSink(path)
        self.sink = sink

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def record(self, record: AuditRecord) -> None:
        line = json.dumps(asdict(record), separators=(",", ":"), default=str)
        self.sink.write(line)

    def new_record(self, principal_id: str, action: str, outcome: str, **kwargs: Any) -> AuditRecord:
        return AuditRecord(
            ts=self._now(),
            principal_id=principal_id,
            action=action,
            outcome=outcome,
            **kwargs,
        )

    def tail(self, n: int = 50) -> List[Dict[str, Any]]:
        """Return the last ``n`` records (newest last). Convenience for the admin surface."""
        return self.sink.tail(n)
