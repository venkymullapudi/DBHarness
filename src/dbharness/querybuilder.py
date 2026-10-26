"""Structured query builder — a typed alternative to raw SQL for agents.

An agent (or any caller) describes *what* it wants with a small, safe vocabulary
— ``find`` / ``insert`` / ``update`` / ``delete`` with typed filters — and the
builder compiles it to a SQL string. That SQL then goes through the **same** gate
pipeline (analyze → policy → rewrite → approval → execute → audit), so this layer
adds zero new enforcement surface: it is purely a safer, friendlier way to
produce the SQL the gate already governs.

Why this is safer than the agent writing SQL:

* No SQL *text* comes from the agent, so there is no SQL-injection surface here —
  identifiers are validated to be plain names and every value is rendered as a
  bound literal via the SQL AST, never string-concatenated.
* ``update``/``delete`` refuse to run without filters unless explicitly told to
  (``all=True``), so a typo can't wipe a table (and the gate would still gate an
  unfiltered write behind approval anyway).

The builder is dialect-aware and returns ``(sql, mode)`` where ``mode`` is
``"read"`` for ``find`` and ``"write"`` otherwise.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union

import sqlglot
from sqlglot import exp

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Comparison operators exposed to callers -> AST builders.
_OPS = {
    "eq", "ne", "lt", "lte", "gt", "gte", "in", "nin", "like", "ilike",
    "is_null", "not_null",
}

# A filter is either the structured form
#   {"column": "status", "op": "eq", "value": "open"}
# or dict shorthand {"status": "open"} (implicit eq), possibly many keys.
Filter = Dict[str, Any]
Filters = Union[Dict[str, Any], List[Filter], None]


class QueryBuilderError(ValueError):
    """Raised when a structured request is malformed or unsafe."""


def _ident(name: str, *, allow_schema: bool = False) -> str:
    """Validate an identifier (optionally ``schema.table``) and return it."""
    if not isinstance(name, str) or not name:
        raise QueryBuilderError(f"invalid identifier: {name!r}")
    parts = name.split(".")
    if len(parts) == 2 and allow_schema:
        pass
    elif len(parts) != 1:
        raise QueryBuilderError(f"invalid identifier: {name!r}")
    for part in parts:
        if not _IDENT.match(part):
            raise QueryBuilderError(f"invalid identifier component: {part!r}")
    return name


def _table(name: str, default_schema: Optional[str] = None) -> "exp.Table":
    _ident(name, allow_schema=True)
    # Drop a leading default-schema qualifier (e.g. "public.") so the emitted SQL
    # is a bare table name. This works everywhere: Postgres/MySQL resolve it via
    # the search path / current database, and SQLite (which has no schemas) would
    # otherwise fail on "public.tickets". A non-default schema is kept verbatim.
    if default_schema and "." in name:
        schema, leaf = name.split(".", 1)
        if schema.lower() == default_schema.lower():
            name = leaf
    return exp.to_table(name)


def _col(name: str) -> "exp.Column":
    return exp.column(_ident(name))


def _lit(value: Any) -> "exp.Expression":
    if value is None:
        return exp.null()
    if isinstance(value, bool):
        return exp.true() if value else exp.false()
    if isinstance(value, (int, float)):
        return exp.Literal.number(value)
    return exp.Literal.string(str(value))


def _condition(f: Filter) -> "exp.Expression":
    col = _col(f["column"])
    op = str(f.get("op", "eq")).lower()
    if op not in _OPS:
        raise QueryBuilderError(f"unsupported operator {op!r}")
    val = f.get("value")
    if op == "eq":
        return exp.EQ(this=col, expression=_lit(val))
    if op == "ne":
        return exp.NEQ(this=col, expression=_lit(val))
    if op == "lt":
        return exp.LT(this=col, expression=_lit(val))
    if op == "lte":
        return exp.LTE(this=col, expression=_lit(val))
    if op == "gt":
        return exp.GT(this=col, expression=_lit(val))
    if op == "gte":
        return exp.GTE(this=col, expression=_lit(val))
    if op in ("in", "nin"):
        if not isinstance(val, (list, tuple)) or not val:
            raise QueryBuilderError(f"{op!r} needs a non-empty list value")
        node: exp.Expression = exp.In(this=col, expressions=[_lit(v) for v in val])
        return exp.Not(this=node) if op == "nin" else node
    if op in ("like", "ilike"):
        klass = exp.ILike if op == "ilike" else exp.Like
        return klass(this=col, expression=_lit(val))
    if op == "is_null":
        return exp.Is(this=col, expression=exp.null())
    if op == "not_null":
        return exp.Not(this=exp.Is(this=col, expression=exp.null()))
    raise QueryBuilderError(f"unsupported operator {op!r}")  # pragma: no cover


def _normalize_filters(filters: Filters) -> List[Filter]:
    if filters is None:
        return []
    if isinstance(filters, dict):
        return [{"column": k, "op": "eq", "value": v} for k, v in filters.items()]
    if isinstance(filters, list):
        out = []
        for f in filters:
            if not isinstance(f, dict) or "column" not in f:
                raise QueryBuilderError(f"invalid filter entry: {f!r}")
            out.append(f)
        return out
    raise QueryBuilderError("filters must be a dict, a list of dicts, or None")


def _where(filters: List[Filter]) -> "Optional[exp.Expression]":
    conds = [_condition(f) for f in filters]
    if not conds:
        return None
    combined = conds[0]
    for c in conds[1:]:
        combined = exp.And(this=combined, expression=c)
    return combined


def build_find(
    table: str,
    filters: Filters = None,
    columns: Optional[List[str]] = None,
    order_by: Optional[List[Dict[str, Any]]] = None,
    limit: Optional[int] = None,
    count: bool = False,
    dialect: str = "postgres",
    default_schema: Optional[str] = None,
) -> Tuple[str, str]:
    tbl = _table(table, default_schema)
    if count:
        selects: List[exp.Expression] = [exp.Count(this=exp.Star())]
    elif columns:
        selects = [_col(c) for c in columns]
    else:
        selects = [exp.Star()]
    select = exp.select(*selects).from_(tbl)
    where = _where(_normalize_filters(filters))
    if where is not None:
        select = select.where(where)
    for ob in order_by or []:
        col = _col(ob["column"])
        select = select.order_by(exp.Ordered(this=col, desc=bool(ob.get("desc"))))
    if limit is not None:
        if not isinstance(limit, int) or limit < 0:
            raise QueryBuilderError("limit must be a non-negative integer")
        select = select.limit(limit)
    return select.sql(dialect=dialect), "read"


def build_insert(table: str, values: Dict[str, Any], dialect: str = "postgres",
                 default_schema: Optional[str] = None) -> Tuple[str, str]:
    if not isinstance(values, dict) or not values:
        raise QueryBuilderError("insert needs a non-empty 'values' dict")
    cols = [_col(c) for c in values]
    schema = exp.Schema(this=_table(table, default_schema), expressions=cols)
    row = exp.tuple_(*[_lit(v) for v in values.values()])
    insert = exp.Insert(this=schema, expression=exp.Values(expressions=[row]))
    return insert.sql(dialect=dialect), "write"


def build_update(
    table: str,
    values: Dict[str, Any],
    filters: Filters = None,
    all: bool = False,
    dialect: str = "postgres",
    default_schema: Optional[str] = None,
) -> Tuple[str, str]:
    if not isinstance(values, dict) or not values:
        raise QueryBuilderError("update needs a non-empty 'values' dict")
    norm = _normalize_filters(filters)
    if not norm and not all:
        raise QueryBuilderError(
            "refusing to UPDATE without filters; pass filters or all=True")
    eqs = [exp.EQ(this=_col(c), expression=_lit(v)) for c, v in values.items()]
    update = exp.Update(this=_table(table, default_schema), expressions=eqs)
    where = _where(norm)
    if where is not None:
        update.set("where", exp.Where(this=where))
    return update.sql(dialect=dialect), "write"


def build_delete(
    table: str,
    filters: Filters = None,
    all: bool = False,
    dialect: str = "postgres",
    default_schema: Optional[str] = None,
) -> Tuple[str, str]:
    norm = _normalize_filters(filters)
    if not norm and not all:
        raise QueryBuilderError(
            "refusing to DELETE without filters; pass filters or all=True")
    delete = exp.Delete(this=_table(table, default_schema))
    where = _where(norm)
    if where is not None:
        delete.set("where", exp.Where(this=where))
    return delete.sql(dialect=dialect), "write"


def build(op: str, dialect: str = "postgres",
          default_schema: Optional[str] = None, **kwargs: Any) -> Tuple[str, str]:
    """Dispatch a structured op name to the matching builder. Returns (sql, mode)."""
    op = op.lower()
    builders = {
        "find": build_find,
        "insert": build_insert,
        "update": build_update,
        "delete": build_delete,
    }
    if op not in builders:
        raise QueryBuilderError(
            f"unknown op {op!r} (use find/insert/update/delete)")
    return builders[op](dialect=dialect, default_schema=default_schema, **kwargs)
