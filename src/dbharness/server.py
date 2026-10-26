"""The MCP server — DBHarness's agent-facing surface.

An AI agent connects over MCP and sees a small set of tools instead of a raw
database connection. Each connection is authenticated to exactly one principal
(via ``DBHARNESS_API_KEY``), and every tool call is routed through :class:`Gate`,
so the policy engine, SQL rewriter, PAM broker and audit log all apply — there
is no path from a tool call to the database that skips enforcement.

Agent tools:      ``whoami``, ``list_tables``, ``describe_table``, ``query``,
                  ``execute``, ``run_approved``.
Operator tools:   ``list_pending_approvals``, ``decide_approval``, ``elevate``,
                  ``audit_tail`` — restricted to principals holding the ``admin``
                  role.

Run it over stdio with ``dbharness`` (see the console-script entry point) or
``python -m dbharness.server``.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List

from dbharness.config import Settings, build_gate
from dbharness.gate import AuthError, Gate
from dbharness.pam import PamError
from dbharness.policy.models import Principal

# The high-level server class is FastMCP in mcp 1.x and MCPServer in mcp 2.x;
# both expose the same .tool()/.run()/.list_tools() surface and lifespan kwarg.
try:
    from mcp.server.mcpserver import MCPServer as _Server  # mcp >= 2.0
except ImportError:  # pragma: no cover
    try:
        from mcp.server.fastmcp import FastMCP as _Server  # mcp 1.x
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "The 'mcp' package (Python >=3.10) is required to run the server. "
            "Install with: pip install -e ."
        ) from exc


# Module-level singletons, initialized in main(). The MCP tool functions close
# over these.
_gate: Gate = None  # type: ignore[assignment]
_principal: Principal = None  # type: ignore[assignment]
_settings: Settings = None  # type: ignore[assignment]


def _require_admin() -> None:
    if "admin" not in _gate.effective_roles(_principal):
        raise PermissionError("this operation requires the 'admin' role")


@asynccontextmanager
async def _lifespan(_server):
    await _gate.executor.connect()
    if _settings.seed_sql:
        with open(_settings.seed_sql, "r", encoding="utf-8") as fh:
            await _gate.executor.run_script(fh.read())
    try:
        yield {}
    finally:
        await _gate.executor.close()


mcp = _Server("dbharness", lifespan=_lifespan)


# -- agent tools -------------------------------------------------------------


@mcp.tool()
async def whoami() -> Dict[str, Any]:
    """Return the calling agent's identity, roles (including any active elevation), and context."""
    return {
        "principal": _principal.id,
        "owner": _principal.owner,
        "roles": _principal.roles,
        "active_elevated_roles": _gate.pam.active_roles(_principal.id),
        "context": _principal.context,
    }


@mcp.tool()
async def list_tables() -> List[str]:
    """List the tables this agent is permitted to read (policy-filtered)."""
    return await _gate.list_tables(_principal)


@mcp.tool()
async def describe_table(table: str) -> Dict[str, Any]:
    """Describe a table's columns. Only tables the agent may read are described."""
    allowed = await _gate.list_tables(_principal)
    normalized = table if "." in table else f"public.{table}"
    if normalized.lower() not in {t.lower() for t in allowed}:
        return {"status": "denied", "reason": f"not permitted to read {table}"}
    return {"status": "ok", "table": normalized,
            "columns": await _gate.executor.describe(normalized)}


@mcp.tool()
async def query(sql: str) -> Dict[str, Any]:
    """Run a read-only (SELECT) query. The gate injects row filters and blocks redacted columns.

    Returns rows on success, a denial reason if policy forbids it, or an
    ``approval_id`` if the operation needs human sign-off.
    """
    result = await _gate.handle_sql(_principal, sql, mode="read")
    return result.to_dict()


@mcp.tool()
async def execute(sql: str) -> Dict[str, Any]:
    """Run a write (INSERT / UPDATE / DELETE). Row filters are enforced; risky writes may require approval.

    On a ``pending_approval`` result, an operator must approve, after which the
    agent calls ``run_approved`` with the returned ``approval_id``.
    """
    result = await _gate.handle_sql(_principal, sql, mode="write")
    return result.to_dict()


@mcp.tool()
async def run_approved(approval_id: str) -> Dict[str, Any]:
    """Execute a statement that an operator has approved, exactly as it was approved."""
    result = await _gate.run_approved(_principal, approval_id)
    return result.to_dict()


# -- structured tools (compile to SQL, enforced by the same gate) -------------
#
# A friendlier, no-SQL interface for agents. `filters` is a JSON object of
# {column: value} (equality) or a list of {"column","op","value"} where op is one
# of eq/ne/lt/lte/gt/gte/in/nin/like/ilike/is_null/not_null.


@mcp.tool()
async def find(table: str, filters: Any = None, columns: Any = None,
               order_by: Any = None, limit: Any = None) -> Dict[str, Any]:
    """Read rows from a table without writing SQL. Row filters and column redaction still apply."""
    return (await _gate.run_structured(
        _principal, "find", table=table, filters=filters, columns=columns,
        order_by=order_by, limit=limit)).to_dict()


@mcp.tool()
async def insert(table: str, values: Dict[str, Any]) -> Dict[str, Any]:
    """Insert a row. The scope column is pinned to the principal's context by the gate."""
    return (await _gate.run_structured(_principal, "insert", table=table, values=values)).to_dict()


@mcp.tool()
async def update(table: str, values: Dict[str, Any], filters: Any = None,
                 all: bool = False) -> Dict[str, Any]:
    """Update rows matching filters (required unless all=True). Risky writes may need approval."""
    return (await _gate.run_structured(
        _principal, "update", table=table, values=values, filters=filters, all=all)).to_dict()


@mcp.tool()
async def delete(table: str, filters: Any = None, all: bool = False) -> Dict[str, Any]:
    """Delete rows matching filters (required unless all=True). Deletes are policy-gated."""
    return (await _gate.run_structured(
        _principal, "delete", table=table, filters=filters, all=all)).to_dict()


@mcp.tool()
async def ask(text: str, confirm: bool = False) -> Dict[str, Any]:
    """Ask the database in plain English (e.g. "show open tickets", "how many customers").

    Reads run immediately (still RBAC- and redaction-enforced). A write returns a
    preview of the exact statement it compiled to and requires confirm=True to
    execute — so natural language never silently changes data. The reply always
    echoes how the request was interpreted.
    """
    return (await _gate.run_nl(_principal, text, confirm=confirm)).to_dict()


# -- operator tools (admin role required) ------------------------------------


@mcp.tool()
async def list_pending_approvals() -> Dict[str, Any]:
    """[admin] List write operations awaiting human approval."""
    _require_admin()
    return {"pending": [
        {"approval_id": a.id, "principal": a.principal_id, "action": a.action,
         "risk": a.risk, "sql": a.effective_sql, "reason": a.reason,
         "expires_at": a.expires_at.isoformat()}
        for a in _gate.pam.list_pending()
    ]}


@mcp.tool()
async def decide_approval(approval_id: str, approve: bool, note: str = "") -> Dict[str, Any]:
    """[admin] Approve or reject a pending write. Approval binds to the exact statement submitted."""
    _require_admin()
    try:
        approval = _gate.pam.decide(approval_id, approve, approver=_principal.id)
    except PamError as exc:
        return {"status": "error", "reason": str(exc)}
    _gate.audit.record(_gate.audit.new_record(
        _principal.id, "decide_approval", "executed",
        reason=f"{'approved' if approve else 'denied'} {approval_id}: {note}",
        approval_id=approval_id,
    ))
    return {"status": "ok", "approval_id": approval.id, "new_status": approval.status.value}


@mcp.tool()
async def elevate(principal_id: str, role: str, minutes: int = 15) -> Dict[str, Any]:
    """[admin] Grant a principal a role for a bounded window (just-in-time elevation)."""
    _require_admin()
    if principal_id not in _gate.policy.principals:
        return {"status": "error", "reason": f"unknown principal {principal_id!r}"}
    if role not in _gate.policy.roles:
        return {"status": "error", "reason": f"unknown role {role!r}"}
    elevation = _gate.pam.elevate(principal_id, role, granted_by=_principal.id, minutes=minutes)
    _gate.audit.record(_gate.audit.new_record(
        _principal.id, "elevate", "executed",
        reason=f"granted {role} to {principal_id} for {minutes}m",
    ))
    return {"status": "ok", "principal": principal_id, "role": role,
            "expires_at": elevation.expires_at.isoformat()}


@mcp.tool()
async def audit_tail(n: int = 50) -> Dict[str, Any]:
    """[admin] Return the most recent audit records."""
    _require_admin()
    return {"records": _gate.audit.tail(n)}


def main() -> None:
    global _gate, _principal, _settings
    _settings = Settings.from_env()
    _gate = build_gate(_settings)
    if not _settings.api_key:
        print("DBHARNESS_API_KEY is not set — cannot resolve the calling principal.",
              file=sys.stderr)
        raise SystemExit(2)
    try:
        _principal = _gate.authenticate(_settings.api_key)
    except AuthError as exc:
        print(f"authentication failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(f"DBHarness: authenticated as principal {_principal.id!r} "
          f"(roles: {', '.join(_principal.roles) or 'none'})", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
