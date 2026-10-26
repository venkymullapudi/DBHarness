"""Observability — structured events on every gate decision.

The gate calls ``observer.event(name, **fields)`` at each decision point
(``denied``, ``pending_approval``, ``executed``, ``error``). This is the seam
for metrics, tracing and alerting: point it at Prometheus, OpenTelemetry, a log
pipeline, or the built-in in-memory counter for tests and quick local insight.

The audit log records *what happened* for forensics; the observer reports
*aggregate operational signal* (rates of denials, approvals, errors) for
monitoring. They are intentionally separate.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List

try:  # Protocol is stdlib on 3.8+; guard just in case.
    from typing import Protocol
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore


class Observer(Protocol):
    def event(self, name: str, **fields: Any) -> None: ...


class NullObserver:
    """Default: discard everything (zero overhead)."""

    def event(self, name: str, **fields: Any) -> None:  # noqa: D401
        pass


class LoggingObserver:
    """Emit each event through the standard logging framework."""

    def __init__(self, logger: "logging.Logger | None" = None, level: int = logging.INFO):
        self.log = logger or logging.getLogger("dbharness.events")
        self.level = level

    def event(self, name: str, **fields: Any) -> None:
        self.log.log(self.level, "dbharness.%s %s", name, fields)


class InMemoryMetrics:
    """Accumulate counters and a bounded event log — handy for tests and demos."""

    def __init__(self, keep_events: int = 1000):
        self.counters: "Counter[str]" = Counter()
        self.events: List[Dict[str, Any]] = []
        self._keep = keep_events

    def event(self, name: str, **fields: Any) -> None:
        self.counters[name] += 1
        outcome = fields.get("outcome")
        action = fields.get("action")
        if outcome:
            self.counters[f"{name}.{outcome}"] += 1
        if outcome and action:
            self.counters[f"{outcome}.{action}"] += 1
        self.events.append({"name": name, **fields})
        if len(self.events) > self._keep:
            self.events = self.events[-self._keep:]

    def snapshot(self) -> Dict[str, int]:
        return dict(self.counters)
