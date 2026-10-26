"""The policy decision engine.

Given an authenticated :class:`Principal` and the *analyzed* shape of a SQL
statement (its action, the tables it touches, the columns it references), the
engine returns a :class:`Decision`: allow or deny, plus the concrete
enforcement the rewriter must apply — the row-filter predicates to AND into the
statement and the columns to redact — and whether the operation needs human
approval.

The engine never sees raw SQL; parsing lives in :mod:`dbharness.sql`. That split
keeps authorization logic independent of SQL-dialect quirks and easy to test.

Evaluation rules:

* **Deny by default** — a table with no matching allow permission fails the
  whole statement.
* **Explicit deny wins** — a matching ``deny`` permission rejects immediately.
* **Filters are per-table** — a table's predicate is the OR of the row filters
  from the allow permissions that grant it (any grant that permits the row); if
  any matching grant is unfiltered, the table is unrestricted.
* **Fail closed on unresolved context** — a row filter referencing a context key
  the principal lacks denies the statement rather than running unscoped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from dbharness.policy.models import Action, Effect, Permission, Policy, Principal

_CTX_PLACEHOLDER = re.compile(r"\{ctx\.([a-zA-Z0-9_]+)\}")


@dataclass
class Decision:
    allowed: bool
    reason: str
    # table (normalized schema.table) -> predicate to AND into the statement.
    row_filters: Dict[str, str] = field(default_factory=dict)
    # normalized "schema.table.column" entries the agent may not read.
    deny_columns: Set[str] = field(default_factory=set)
    require_approval: bool = False
    # roles that were consulted, for the audit record.
    effective_roles: List[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def _permissions_for(self, role_names: Iterable[str]) -> List[Permission]:
        perms: List[Permission] = []
        for name in role_names:
            role = self.policy.role(name)
            if role:
                perms.extend(role.permissions)
        return perms

    def evaluate(
        self,
        principal: Principal,
        action: Action,
        tables: Iterable[str],
        columns: Iterable[str] = (),
        extra_roles: Optional[Iterable[str]] = None,
        bare_columns: Iterable[str] = (),
    ) -> Decision:
        """Decide whether ``principal`` may perform ``action`` on ``tables``.

        ``columns`` is the set of ``schema.table.column`` references the
        statement makes; it is checked against ``deny_columns``. ``bare_columns``
        are unqualified column names the analyzer could not pin to a table; they
        are checked conservatively by leaf name (if any denied column shares the
        name, the statement is denied — fail closed). ``extra_roles`` are
        time-boxed roles granted by the PAM broker at request time.
        """
        tables = [t.lower() for t in tables]
        columns = {c.lower() for c in columns}
        bare_columns = {c.lower() for c in bare_columns}
        role_names = list(principal.roles) + list(extra_roles or [])
        decision = Decision(allowed=False, reason="", effective_roles=role_names)

        if not tables:
            decision.reason = "statement references no known table"
            return decision

        perms = self._permissions_for(role_names)

        # 1. Explicit deny wins over everything.
        for perm in perms:
            if perm.effect is Effect.DENY and perm.matches_action(action):
                for table in tables:
                    if perm.matches_resource(table):
                        decision.reason = (
                            f"explicit deny on {table} for action {action.value}"
                        )
                        return decision

        # 2. Every table must be granted by at least one allow permission.
        for table in tables:
            grants = [
                p
                for p in perms
                if p.effect is Effect.ALLOW
                and p.matches_action(action)
                and p.matches_resource(table)
            ]
            if not grants:
                decision.reason = (
                    f"no role grants {action.value} on {table} "
                    f"(roles: {', '.join(role_names) or 'none'})"
                )
                return decision

            # Row filters: OR across grants; an unfiltered grant lifts scoping.
            rendered: List[str] = []
            unrestricted = False
            for grant in grants:
                if grant.row_filter is None:
                    unrestricted = True
                    break
                try:
                    rendered.append(_render_filter(grant.row_filter, principal.context))
                except _MissingContext as exc:
                    decision.reason = (
                        f"row filter for {table} needs context {exc.key!r} "
                        f"which principal {principal.id!r} does not have"
                    )
                    return decision
            if not unrestricted and rendered:
                combined = " OR ".join(f"({r})" for r in rendered)
                decision.row_filters[table] = combined

            # Column redaction and approval requirement come from the grants.
            for grant in grants:
                for col in grant.deny_columns:
                    decision.deny_columns.add(_qualify_deny_column(col, table))
                if grant.require_approval:
                    decision.require_approval = True

        # 3. Reject any explicit reference to a denied column (fail closed).
        for col in columns:
            if _column_is_denied(col, decision.deny_columns):
                decision.reason = f"column {col} is denied to this principal"
                return decision

        # 3b. Conservatively reject unqualified columns whose bare name matches a
        #     denied column's leaf — an agent must not smuggle `ssn` through a
        #     scope the analyzer could not fully resolve.
        denied_leaves = {d.split(".")[-1] for d in decision.deny_columns}
        for name in bare_columns:
            if name in denied_leaves:
                decision.reason = (
                    f"unqualified column {name!r} may reference a redacted column; "
                    "qualify it explicitly"
                )
                return decision

        decision.allowed = True
        decision.reason = "granted"
        return decision


class _MissingContext(Exception):
    def __init__(self, key: str):
        super().__init__(key)
        self.key = key


def _render_filter(template: str, context: Dict[str, str]) -> str:
    """Interpolate ``{ctx.key}`` placeholders with quoted literals.

    Values come from the *policy file* (trusted config), not from agent input,
    but we still render them as proper SQL literals: integers inline bare,
    everything else becomes a single-quoted, escaped string literal.
    """

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key not in context:
            raise _MissingContext(key)
        value = context[key]
        if re.fullmatch(r"-?\d+", value):
            return value
        escaped = value.replace("'", "''")
        return f"'{escaped}'"

    return _CTX_PLACEHOLDER.sub(repl, template)


def _qualify_deny_column(col: str, table: str) -> str:
    """Normalize a permission's deny-column entry to a full schema.table.column.

    A permission may list ``deny_columns`` as ``ssn`` (relative to the table it
    grants) or as ``customers.ssn`` / ``public.customers.ssn`` (explicit).
    """
    parts = col.split(".")
    if len(parts) == 1:
        return f"{table}.{parts[0]}"
    if len(parts) == 2:
        # table.column — inherit the table's schema.
        schema = table.split(".")[0] if "." in table else "public"
        return f"{schema}.{col}"
    return col  # already fully qualified


def _column_is_denied(col: str, deny_set: Set[str]) -> bool:
    """Match a referenced column against the deny set, tolerant of schema omission."""
    col = col.lower()
    if col in deny_set:
        return True
    # Compare on the trailing table.column when schemas differ or are absent.
    tail = ".".join(col.split(".")[-2:])
    for denied in deny_set:
        if ".".join(denied.split(".")[-2:]) == tail:
            return True
    return False
