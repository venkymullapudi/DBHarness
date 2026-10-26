"""The Gate — the enforcement pipeline every agent request flows through.

This is the composition root that wires the policy engine, the SQL guard, the
PAM broker, the audit log and the DB executor into a single deterministic path:

    authenticate → analyze → decide (RBAC) → rewrite (enforce) → risk/approval
    → execute (vaulted creds) → audit

Nothing bypasses it. The MCP server is a thin adapter that turns tool calls into
:class:`Gate` method calls; all of the security logic lives here so it can be
unit-tested without a transport.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from dbharness.audit import AuditLog
from dbharness.db import Executor
from dbharness.observability import NullObserver, Observer
from dbharness.pam import PamBroker, PamError
from dbharness.policy.engine import PolicyEngine
from dbharness.policy.models import Action, Policy, Principal
from dbharness.sql import Risk, SqlGuard, SqlGuardError

_READ_ACTIONS = {Action.SELECT}
_WRITE_ACTIONS = {Action.INSERT, Action.UPDATE, Action.DELETE}


class AuthError(RuntimeError):
    pass


@dataclass
class GateResult:
    """Uniform result envelope returned to the MCP adapter."""

    status: str  # ok | denied | pending_approval | error
    data: Optional[Dict[str, Any]] = None
    reason: str = ""
    approval_id: str = ""
    risk: str = ""
    effective_sql: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": self.status}
        if self.reason:
            out["reason"] = self.reason
        if self.risk:
            out["risk"] = self.risk
        if self.effective_sql:
            out["effective_sql"] = self.effective_sql
        if self.approval_id:
            out["approval_id"] = self.approval_id
        if self.data is not None:
            out["result"] = self.data
        return out


class Gate:
    def __init__(
        self,
        policy: Policy,
        executor: Executor,
        audit: AuditLog,
        pam: Optional[PamBroker] = None,
        guard: Optional[SqlGuard] = None,
        observer: Optional[Observer] = None,
        translator: Optional[Any] = None,
    ):
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.executor = executor
        self.audit = audit
        self.pam = pam or PamBroker()
        self.guard = guard or SqlGuard(
            dialect=executor.dialect,
            default_schema=getattr(executor, "default_schema", "public"),
        )
        self.observer = observer or NullObserver()
        self.translator = translator  # natural-language translator (optional)

    # -- identity -------------------------------------------------------------

    def authenticate(self, api_key: str) -> Principal:
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        principal = self.policy.principal_by_key_hash(key_hash)
        if principal is None:
            raise AuthError("no principal matches the presented API key")
        return principal

    def effective_roles(self, principal: Principal) -> List[str]:
        return list(principal.roles) + self.pam.active_roles(principal.id)

    # -- the main pipeline ----------------------------------------------------

    async def handle_sql(self, principal: Principal, sql: str, mode: str) -> GateResult:
        """Run one statement through the full pipeline.

        ``mode`` is ``"read"`` or ``"write"`` and must match the statement's
        action, so a ``query`` tool can never smuggle in a mutation.
        """
        # 1. Parse + analyze (fails closed on anything not SELECT/INSERT/UPDATE/DELETE).
        try:
            root, analyzed = self.guard.analyze(sql)
        except SqlGuardError as exc:
            return self._deny(principal, "error", raw_sql=sql, reason=str(exc),
                              outcome="error")

        # 2. Enforce the read/write channel separation.
        is_read = analyzed.action in _READ_ACTIONS
        if mode == "read" and not is_read:
            return self._deny(principal, analyzed.action.value, raw_sql=sql,
                              tables=analyzed.tables,
                              reason="use the write channel for a mutation")
        if mode == "write" and is_read:
            return self._deny(principal, analyzed.action.value, raw_sql=sql,
                              tables=analyzed.tables,
                              reason="use the read channel for a SELECT")

        # A statement that touches no known table cannot be authorized.
        if not analyzed.tables:
            return self._deny(principal, analyzed.action.value, raw_sql=sql,
                              reason="statement references no known table",
                              risk=analyzed.risk.value)

        # 3. RBAC decision. The write target is evaluated under the mutating
        #    action; every other table is a *source* and requires SELECT. Both
        #    must pass; their enforcement (row filters, redactions, approval) is
        #    merged.
        extra = self.pam.active_roles(principal.id)
        decision = self._authorize(principal, analyzed, extra)
        if not decision.allowed:
            return self._deny(principal, analyzed.action.value, raw_sql=sql,
                              tables=analyzed.tables, roles=decision.effective_roles,
                              reason=decision.reason, risk=analyzed.risk.value)

        # 4. Rewrite the AST to physically enforce the decision.
        try:
            effective_sql = self.guard.rewrite(
                root,
                decision.row_filters,
                decision.deny_columns,
                analyzed.star_tables,
            )
        except SqlGuardError as exc:
            return self._deny(principal, analyzed.action.value, raw_sql=sql,
                              tables=analyzed.tables, reason=str(exc),
                              risk=analyzed.risk.value)

        # 5. Approval gate: policy-required, or the hard safety net for an
        #    unfiltered mutation (UPDATE/DELETE with no WHERE).
        unfiltered_write = (
            analyzed.action in (Action.UPDATE, Action.DELETE) and not analyzed.has_where
        )
        if decision.require_approval or unfiltered_write:
            approval = self.pam.create_approval(
                principal_id=principal.id,
                action=analyzed.action.value,
                risk=analyzed.risk.value,
                raw_sql=sql,
                effective_sql=effective_sql,
                reason=("policy requires approval" if decision.require_approval
                        else "unfiltered mutation requires approval"),
            )
            self.audit.record(self.audit.new_record(
                principal.id, analyzed.action.value, "pending_approval",
                raw_sql=sql, effective_sql=effective_sql, tables=analyzed.tables,
                risk=analyzed.risk.value, reason=approval.reason,
                roles=decision.effective_roles, approval_id=approval.id,
            ))
            self.observer.event("request", outcome="pending_approval",
                                principal=principal.id, action=analyzed.action.value,
                                tables=analyzed.tables, risk=analyzed.risk.value)
            return GateResult(
                status="pending_approval", approval_id=approval.id,
                risk=analyzed.risk.value, effective_sql=effective_sql,
                reason=approval.reason,
            )

        # 6. Execute with vaulted credentials and audit the outcome.
        return await self._execute(principal, analyzed.action, sql, effective_sql,
                                   analyzed.tables, analyzed.risk,
                                   decision.effective_roles)

    def _authorize(self, principal, analyzed, extra) -> "Decision":
        """Evaluate the write target (under the mutating action) and all source
        tables (under SELECT), then merge into one decision. Denies on the first
        failing sub-evaluation."""
        from dbharness.policy.engine import Decision

        cols = analyzed.column_refs
        bare = analyzed.ambiguous_columns
        merged = Decision(allowed=True, reason="granted",
                          effective_roles=list(principal.roles) + list(extra))

        checks = []
        if analyzed.source_tables:
            checks.append((Action.SELECT, analyzed.source_tables))
        if analyzed.target_table is not None:
            checks.append((analyzed.action, [analyzed.target_table]))

        for act, tables in checks:
            d = self.engine.evaluate(principal, act, tables, cols,
                                     extra_roles=extra, bare_columns=bare)
            if not d.allowed:
                return d
            merged.row_filters.update(d.row_filters)
            merged.deny_columns |= d.deny_columns
            merged.require_approval = merged.require_approval or d.require_approval

        # Read-redaction on the write target: RETURNING (and any column read from
        # the target) is a read and must satisfy SELECT column permissions, which
        # may differ from the write grant. A principal with no read grant on the
        # target keeps a legitimate write-only capability, but may not RETURN
        # columns it cannot read.
        if analyzed.target_table is not None:
            tbl = [analyzed.target_table]
            can_read = self.engine.evaluate(
                principal, Action.SELECT, tbl, extra_roles=extra).allowed
            if can_read:
                dsel = self.engine.evaluate(
                    principal, Action.SELECT, tbl, cols,
                    extra_roles=extra, bare_columns=bare)
                if not dsel.allowed:
                    return dsel  # a returned/referenced column is redacted
                merged.deny_columns |= dsel.deny_columns
            elif analyzed.has_returning:
                merged.allowed = False
                merged.reason = (
                    f"cannot RETURN columns from {analyzed.target_table}: "
                    "no read permission on it"
                )
        return merged

    def explain(self, principal: Principal, sql: str, mode: str = "read") -> Dict[str, Any]:
        """Dry-run a statement: show what the gate *would* do without executing.

        Returns the decision, the rewritten (enforced) SQL, injected row filters,
        redacted columns, and whether human approval would be required. Invaluable
        for reviewing a policy change before it ships — and it never touches the
        database. Powers ``dbharness explain`` on the CLI.
        """
        try:
            root, analyzed = self.guard.analyze(sql)
        except SqlGuardError as exc:
            return {"allowed": False, "stage": "parse", "reason": str(exc)}

        is_read = analyzed.action in _READ_ACTIONS
        if mode == "read" and not is_read:
            return {"allowed": False, "stage": "channel",
                    "reason": "use the write channel for a mutation"}
        if mode == "write" and is_read:
            return {"allowed": False, "stage": "channel",
                    "reason": "use the read channel for a SELECT"}
        if not analyzed.tables:
            return {"allowed": False, "stage": "authorize",
                    "reason": "statement references no known table"}

        extra = self.pam.active_roles(principal.id)
        decision = self._authorize(principal, analyzed, extra)
        base = {"action": analyzed.action.value, "tables": analyzed.tables,
                "risk": analyzed.risk.value}
        if not decision.allowed:
            return {"allowed": False, "stage": "authorize", "reason": decision.reason, **base}

        try:
            effective_sql = self.guard.rewrite(
                root, decision.row_filters, decision.deny_columns, analyzed.star_tables)
        except SqlGuardError as exc:
            return {"allowed": False, "stage": "rewrite", "reason": str(exc), **base}

        unfiltered_write = (
            analyzed.action in (Action.UPDATE, Action.DELETE) and not analyzed.has_where)
        return {
            "allowed": True, **base,
            "effective_sql": effective_sql,
            "requires_approval": decision.require_approval or unfiltered_write,
            "row_filters": decision.row_filters,
            "deny_columns": sorted(decision.deny_columns),
            "effective_roles": decision.effective_roles,
        }

    async def _readable_schema(self, principal: Principal) -> Dict[str, List[str]]:
        """Tables the principal may read, each with its non-redacted columns.

        This is exactly what a natural-language translator is allowed to see — so
        it can only ever produce in-scope requests, and never learns the names of
        tables or columns the principal cannot access.
        """
        extra = self.pam.active_roles(principal.id)
        schema: Dict[str, List[str]] = {}
        for table in await self.list_tables(principal):
            cols = [c["name"] for c in await self.executor.describe(table)]
            decision = self.engine.evaluate(
                principal, Action.SELECT, [table], extra_roles=extra)
            denied = {d.split(".")[-1].lower() for d in decision.deny_columns}
            schema[table] = [c for c in cols if c.lower() not in denied]
        return schema

    async def run_nl(self, principal: Principal, text: str,
                     translator: Optional[Any] = None,
                     confirm: bool = False) -> GateResult:
        """Answer a natural-language request against the database.

        Flow: translate English → a candidate request (structured op or SQL),
        scoped to what the principal can read → run through the normal pipeline.
        Reads execute; writes return a **preview** (compiled SQL + decision) and
        require ``confirm=True`` before they run — a human-in-the-loop check so
        words never silently mutate data. The translator is untrusted; the gate
        still enforces RBAC, row filters, redaction and approval on the result.
        """
        from dbharness.nl import NLError, RuleBasedTranslator
        from dbharness.querybuilder import QueryBuilderError, build

        tr = translator or self.translator or RuleBasedTranslator()
        schema = await self._readable_schema(principal)
        try:
            req = tr.translate(text, schema=schema, context=principal.context)
        except NLError as exc:
            self.observer.event("request", outcome="not_understood",
                                principal=principal.id, action="nl")
            return GateResult(status="error", reason=str(exc))

        # Compile the candidate to a concrete SQL string + read/write mode.
        if req.kind == "sql":
            sql, mode = req.sql or "", ("write" if req.mode == "write" else "read")
        else:
            try:
                sql, mode = build(req.op, dialect=self.guard.dialect,
                                  default_schema=self.guard.default_schema, **req.kwargs)
            except QueryBuilderError as exc:
                return GateResult(status="error", reason=str(exc))

        interpretation = {"interpretation": req.interpreted,
                          "request": {"kind": req.kind, "op": req.op, **(req.kwargs or {})}}

        if mode == "write" and not confirm:
            # Preview only: show exactly what the words compiled to, don't run it.
            preview = self.explain(principal, sql, mode)
            data = {**interpretation, "compiled_sql": sql, "preview": preview}
            if not preview.get("allowed"):
                # No point asking to confirm a write the policy would reject.
                return GateResult(status="denied", data=data,
                                  reason=preview.get("reason", "not permitted"))
            return GateResult(status="needs_confirmation", data=data,
                              reason="natural-language write — confirm to run",
                              effective_sql=preview.get("effective_sql", ""))

        res = await self.handle_sql(principal, sql, mode)
        if res.data is None:
            res.data = {}
        res.data.update(interpretation)
        return res

    async def run_structured(self, principal: Principal, op: str, **kwargs: Any) -> GateResult:
        """Run a structured (find/insert/update/delete) request.

        Compiles the typed request to SQL with :mod:`dbharness.querybuilder`, then
        runs it through the exact same pipeline as raw SQL — so all enforcement
        (row filters, redaction, approval, audit) applies unchanged. The agent
        never authors SQL text.
        """
        from dbharness.querybuilder import QueryBuilderError, build

        try:
            sql, mode = build(op, dialect=self.guard.dialect,
                              default_schema=self.guard.default_schema, **kwargs)
        except QueryBuilderError as exc:
            return self._deny(principal, f"structured:{op}", reason=str(exc),
                              outcome="error")
        return await self.handle_sql(principal, sql, mode)

    async def run_approved(self, principal: Principal, approval_id: str) -> GateResult:
        """Execute a previously-approved statement (exactly as approved)."""
        try:
            effective_sql = self.pam.consume(approval_id, principal.id)
            approval = self.pam.get_approval(approval_id)
        except PamError as exc:
            return self._deny(principal, "run_approved", reason=str(exc),
                              outcome="error")
        action = Action(approval.action)
        return await self._execute(principal, action, approval.raw_sql, effective_sql,
                                   [], Risk(approval.risk), self.effective_roles(principal),
                                   approval_id=approval_id)

    async def _execute(
        self, principal: Principal, action: Action, raw_sql: str, effective_sql: str,
        tables: List[str], risk: Risk, roles: List[str], approval_id: str = "",
    ) -> GateResult:
        session = self._session_for(principal)
        try:
            if action in _READ_ACTIONS:
                result = await self.executor.query(effective_sql, session=session)
                data, rows = result.to_dict(), result.rowcount
            else:
                result = await self.executor.execute(effective_sql, session=session)
                data, rows = result.to_dict(), result.rowcount
        except Exception as exc:  # noqa: BLE001 - surface DB errors to the agent, audited
            self.audit.record(self.audit.new_record(
                principal.id, action.value, "error", raw_sql=raw_sql,
                effective_sql=effective_sql, tables=tables, risk=risk.value,
                roles=roles, error=str(exc), approval_id=approval_id or None,
            ))
            self.observer.event("request", outcome="error", principal=principal.id,
                                action=action.value, tables=tables, risk=risk.value,
                                error=str(exc))
            return GateResult(status="error", reason=f"database error: {exc}",
                              effective_sql=effective_sql)

        self.audit.record(self.audit.new_record(
            principal.id, action.value, "executed", raw_sql=raw_sql,
            effective_sql=effective_sql, tables=tables, risk=risk.value,
            roles=roles, rows=rows, approval_id=approval_id or None,
        ))
        self.observer.event("request", outcome="executed", principal=principal.id,
                            action=action.value, tables=tables, risk=risk.value, rows=rows)
        return GateResult(status="ok", data=data, risk=risk.value,
                          effective_sql=effective_sql)

    @staticmethod
    def _session_for(principal: Principal) -> Optional[Dict[str, Any]]:
        """Map a principal's context into ``dbharness.<key>`` session GUCs.

        These are handed to the database on every execution so row-level-security
        policies can enforce the same scoping as defense-in-depth. Harmless when
        RLS is not configured — the settings are simply unused.
        """
        if not principal.context:
            return None
        return {f"dbharness.{k}": str(v) for k, v in principal.context.items()}

    # -- schema introspection (policy-filtered) -------------------------------

    async def list_tables(self, principal: Principal) -> List[str]:
        """List only the tables this principal can SELECT from."""
        all_tables = await self.executor.list_tables()
        allowed: List[str] = []
        extra = self.pam.active_roles(principal.id)
        for table in all_tables:
            decision = self.engine.evaluate(
                principal, Action.SELECT, [table], extra_roles=extra
            )
            if decision.allowed:
                allowed.append(table)
        return allowed

    # -- helpers --------------------------------------------------------------

    def _deny(
        self, principal: Principal, action: str, reason: str, raw_sql: str = "",
        tables: Optional[List[str]] = None, roles: Optional[List[str]] = None,
        risk: str = "", outcome: str = "denied",
    ) -> GateResult:
        self.audit.record(self.audit.new_record(
            principal.id, action, outcome, raw_sql=raw_sql, tables=tables or [],
            reason=reason, roles=roles or [], risk=risk,
        ))
        self.observer.event("request", outcome=outcome, principal=principal.id,
                            action=action, tables=tables or [], risk=risk, reason=reason)
        return GateResult(status="error" if outcome == "error" else "denied",
                          reason=reason, risk=risk)
