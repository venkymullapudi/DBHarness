"""The RBAC data model.

A ``Policy`` is the whole configured world: the principals (agents), the roles,
and — implicitly through roles — the permissions. Everything here is plain data;
the decision logic lives in :mod:`dbharness.policy.engine`.

Design rules baked into the model:

* **Deny by default.** A principal can do nothing until a role grants it.
* **Least privilege is expressible down to the row and column.** A permission
  scopes an :class:`Action` to a set of table resources, and may attach a
  ``row_filter`` (injected as a ``WHERE`` predicate) and ``deny_columns``
  (redacted / blocked on read).
* **Risk is a first-class property.** A permission can require human approval,
  making a privileged write a two-party operation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class Action(str, enum.Enum):
    """The kind of operation an agent is attempting.

    These map onto SQL command families rather than individual statements, so
    the policy stays readable ("this role may SELECT and INSERT") instead of
    enumerating syntax.
    """

    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    # DDL and anything else is deliberately not grantable in the MVP: the gate
    # blocks schema changes outright. They can be added as explicit actions.

    @classmethod
    def from_sql_kind(cls, kind: str) -> "Optional[Action]":
        """Map a sqlglot expression class name to an Action, or None if ungrantable."""
        return _SQL_KIND_TO_ACTION.get(kind.lower())


_SQL_KIND_TO_ACTION = {
    "select": Action.SELECT,
    "union": Action.SELECT,
    "insert": Action.INSERT,
    "update": Action.UPDATE,
    "delete": Action.DELETE,
}


class Effect(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"  # explicit deny always wins over any allow


@dataclass(frozen=True)
class Permission:
    """A single grant (or explicit denial) within a role.

    ``resources`` are ``schema.table`` identifiers; ``"*"`` matches any table and
    ``"schema.*"`` matches any table in a schema. ``row_filter`` is a SQL boolean
    expression that may reference principal context as ``{ctx.key}`` (e.g.
    ``"tenant_id = {ctx.tenant_id}"``); the engine renders it and the rewriter
    ANDs it into the statement so the agent physically cannot exceed the grant.
    """

    effect: Effect
    actions: frozenset  # frozenset[Action]
    resources: frozenset  # frozenset[str], normalized lower-case schema.table
    row_filter: Optional[str] = None
    deny_columns: frozenset = frozenset()  # frozenset[str], "table.column"
    require_approval: bool = False
    description: str = ""

    def matches_action(self, action: Action) -> bool:
        return action in self.actions

    def matches_resource(self, resource: str) -> bool:
        resource = resource.lower()
        if "*" in self.resources:
            return True
        if resource in self.resources:
            return True
        # schema-wildcard, e.g. "public.*"
        schema = resource.split(".")[0] if "." in resource else None
        if schema and f"{schema}.*" in self.resources:
            return True
        return False


@dataclass(frozen=True)
class Role:
    """A named bundle of permissions."""

    name: str
    permissions: List[Permission] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class Principal:
    """An authenticated caller — almost always an AI agent.

    ``api_key_sha256`` is the hex SHA-256 of the agent's key; the raw key is
    never stored. ``context`` carries attributes (tenant, region, owner) that
    row filters interpolate. ``roles`` are the statically-granted roles; the PAM
    broker may layer time-boxed roles on top at runtime.
    """

    id: str
    api_key_sha256: str
    roles: List[str] = field(default_factory=list)
    context: Dict[str, str] = field(default_factory=dict)
    owner: str = ""  # the human/team accountable for this agent
    description: str = ""


@dataclass
class Policy:
    """The fully-loaded policy: principals + roles, indexed for lookup."""

    principals: Dict[str, Principal] = field(default_factory=dict)
    roles: Dict[str, Role] = field(default_factory=dict)

    def principal_by_key_hash(self, key_hash: str) -> Optional[Principal]:
        for p in self.principals.values():
            if p.api_key_sha256 == key_hash:
                return p
        return None

    def role(self, name: str) -> Optional[Role]:
        return self.roles.get(name)
