"""Parse, validate, risk-classify and rewrite a single SQL statement.

The :class:`SqlGuard` is where a policy decision becomes a concrete, safe
statement. It is the security-critical core of the gate, so it is deliberately
strict: it accepts only statement shapes it can *prove* it enforces, and fails
closed on everything else.

Flow:

1. **Parse** exactly one statement (reject multi-statement payloads).
2. **Structurally validate** (:meth:`analyze`): reject anything that is not a
   plain SELECT / set-op / INSERT / UPDATE / DELETE at the root; reject any
   data-modifying operation *nested* in the tree (Postgres data-modifying CTEs
   are a SELECT that writes); reject ``SELECT INTO``; reject a configurable
   denylist of dangerous functions (``pg_read_file``, ``lo_import``,
   ``load_extension`` …).
3. **Analyze** the tables, per-scope column references, and risk.
4. The caller (:class:`~dbharness.gate.Gate`) asks the policy engine to decide.
5. **Rewrite** (:meth:`rewrite`) to physically enforce the decision:

   * Every *source* occurrence of a filtered table is replaced by a filtered
     derived table — ``tickets`` becomes ``(SELECT * FROM tickets WHERE
     tenant_id='acme') AS tickets``. Because the filter lives inside the
     derived table, it binds correctly no matter how deeply the table is nested
     (subquery, CTE, JOIN, self-join), which a top-level ``WHERE`` cannot.
   * The *target* of an UPDATE/DELETE (which cannot be a derived table) gets the
     filter ANDed into its WHERE, qualified to the target.
   * An INSERT into a filtered table has the scoping column value pinned to the
     principal's context (auto-filled if omitted, rejected if forged).
   * An UPDATE may not SET a scoping column (no cross-partition moves).
   * A wildcard (``*`` / ``t.*``) over a table with a redacted column is
     rejected.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import sqlglot
from sqlglot import exp

from dbharness.policy.models import Action


class SqlGuardError(ValueError):
    """Raised when a statement cannot be safely accepted or rewritten."""


class Risk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Root expression types we will handle. A set-operation (UNION/EXCEPT/INTERSECT)
# is a read; sqlglot models Except/Intersect as subclasses of Union.
_READ_ROOTS = (exp.Select, exp.Union)
_WRITE_ROOTS = (exp.Insert, exp.Update, exp.Delete)

# Scope owners for column resolution: a column resolves against the nearest one.
_SCOPES = (exp.Select, exp.Update, exp.Delete)

# Functions that read the filesystem, reach the network, run code, or enable DoS.
# Matched case-insensitively against function names anywhere in the tree.
_DEFAULT_BLOCKED_FUNCTIONS = frozenset({
    # PostgreSQL
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "pg_read_server_files", "lo_import", "lo_export", "lo_get", "lo_put",
    "dblink", "dblink_exec", "dblink_connect", "pg_sleep", "pg_sleep_for",
    "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
    "set_config", "current_setting", "query_to_xml", "copy_from", "copy_to",
    # MySQL
    "load_file", "sys_exec", "sys_eval", "benchmark", "sleep",
    # SQLite
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
    # SQL Server-ish / generic
    "xp_cmdshell", "openrowset", "openquery", "system", "exec", "eval",
})


@dataclass
class AnalyzedStatement:
    action: Action  # the root action (target action for a write)
    tables: List[str]  # every base table, normalized schema.table, appearance order
    target_table: Optional[str]  # write target (None for reads)
    source_tables: List[str]  # tables read as sources (require SELECT)
    column_refs: Set[str] = field(default_factory=set)  # qualified schema.table.column
    ambiguous_columns: Set[str] = field(default_factory=set)  # unresolved bare names
    star_tables: Set[str] = field(default_factory=set)  # tables exposed via * / t.*
    has_where: bool = False
    has_returning: bool = False  # RETURNING outputs rows — a read on the target
    risk: Risk = Risk.LOW
    risk_reason: str = ""


class SqlGuard:
    def __init__(
        self,
        dialect: str = "postgres",
        default_schema: str = "public",
        blocked_functions: Optional[Set[str]] = None,
    ):
        self.dialect = dialect
        self.default_schema = default_schema
        self.blocked_functions = frozenset(
            f.lower() for f in (blocked_functions if blocked_functions is not None
                                else _DEFAULT_BLOCKED_FUNCTIONS)
        )

    # -- public API -----------------------------------------------------------

    def analyze(self, sql: str) -> Tuple["exp.Expression", AnalyzedStatement]:
        """Parse, structurally validate, and analyze — or raise :class:`SqlGuardError`."""
        try:
            statements = sqlglot.parse(sql, dialect=self.dialect)
        except Exception as exc:  # sqlglot raises several parse error types
            raise SqlGuardError(f"could not parse SQL: {exc}") from exc

        statements = [s for s in statements if s is not None]
        if not statements:
            raise SqlGuardError("empty statement")
        if len(statements) > 1:
            raise SqlGuardError("multiple statements are not allowed; submit exactly one")

        root = statements[0]
        self._structural_check(root)

        action = self._root_action(root)
        analyzed = self._analyze_tree(root, action)
        return root, analyzed

    def rewrite(
        self,
        root: "exp.Expression",
        row_filters: Dict[str, str],
        deny_columns: Set[str],
        star_tables: Set[str],
    ) -> str:
        """Enforce the decision on the AST and return the final SQL string."""
        # 1. Refuse wildcards that could leak a redacted column.
        denied_tables = {".".join(c.split(".")[:-1]) for c in deny_columns}
        leaking = {t for t in star_tables if t in denied_tables}
        if leaking:
            raise SqlGuardError(
                "wildcard select ('*') is not allowed on " + ", ".join(sorted(leaking))
                + " because it has redacted columns; list explicit columns instead"
            )

        target_node = self._target_table_node(root)
        target_norm = self._normalize_table(target_node) if target_node is not None else None

        # 2. Wrap every *source* occurrence of a filtered table in a filtered
        #    derived table. Snapshot the node list first (we mutate the tree).
        for node in list(root.find_all(exp.Table)):
            norm = self._normalize_table(node)
            if norm not in row_filters:
                continue
            if node is target_node:
                continue  # the write target is handled below, not wrapped
            self._wrap_source(node, row_filters[norm])

        # 3. Enforce the filter on the write target.
        if target_norm is not None and target_norm in row_filters:
            predicate = row_filters[target_norm]
            if isinstance(root, exp.Insert):
                self._enforce_insert(root, target_node, predicate)
            elif isinstance(root, exp.Update):
                self._block_scoping_update(root, predicate)
                self._inject_target_where(root, target_node, predicate)
            elif isinstance(root, exp.Delete):
                self._inject_target_where(root, target_node, predicate)

        return root.sql(dialect=self.dialect)

    # -- structural validation ------------------------------------------------

    def _structural_check(self, root: "exp.Expression") -> None:
        if not isinstance(root, _READ_ROOTS + _WRITE_ROOTS):
            raise SqlGuardError(
                f"statement type {type(root).__name__.lower()!r} is not permitted "
                "(only SELECT / UNION / INSERT / UPDATE / DELETE)"
            )

        # No data-modifying operation may appear anywhere except as the root.
        # This blocks Postgres data-modifying CTEs (a SELECT that writes) and any
        # DML smuggled into a subquery.
        for node in root.find_all(*_WRITE_ROOTS):
            if node is not root:
                raise SqlGuardError(
                    "a data-modifying statement (INSERT/UPDATE/DELETE) is only allowed "
                    "as the top-level statement, not nested in a CTE or subquery"
                )

        # SELECT ... INTO creates a table — reject it.
        if root.find(exp.Into) is not None:
            raise SqlGuardError("SELECT ... INTO is not permitted")

        # Command/Copy nodes (COPY ... TO PROGRAM, backslash commands) — reject.
        for name in ("Command", "Copy"):
            klass = getattr(exp, name, None)
            if klass is not None and root.find(klass) is not None:
                raise SqlGuardError(f"{name.lower()} operations are not permitted")

        # Dangerous function calls anywhere in the tree.
        for fn in root.find_all(exp.Func, exp.Anonymous):
            name = (fn.name or getattr(fn, "sql_name", lambda: "")()).lower()
            if name in self.blocked_functions:
                raise SqlGuardError(f"function {name!r} is not permitted")

    def _root_action(self, root: "exp.Expression") -> Action:
        if isinstance(root, _READ_ROOTS):
            return Action.SELECT
        if isinstance(root, exp.Insert):
            return Action.INSERT
        if isinstance(root, exp.Update):
            return Action.UPDATE
        if isinstance(root, exp.Delete):
            return Action.DELETE
        raise SqlGuardError(f"unsupported statement: {type(root).__name__}")

    # -- analysis -------------------------------------------------------------

    def _analyze_tree(self, root: "exp.Expression", action: Action) -> AnalyzedStatement:
        cte_names = self._cte_names(root)
        tables = self._extract_tables(root, cte_names)
        target_node = self._target_table_node(root)
        target_norm = self._normalize_table(target_node) if target_node is not None else None
        source_tables = [t for t in tables if t != target_norm] if target_norm else list(tables)

        column_refs, ambiguous = self._extract_columns(root, cte_names)
        star_tables = self._extract_stars(root, tables, cte_names)
        has_where = root.find(exp.Where) is not None
        has_returning = getattr(exp, "Returning", None) is not None and \
            root.find(exp.Returning) is not None
        risk, reason = self._classify_risk(action, has_where, bool(star_tables))

        return AnalyzedStatement(
            action=action, tables=tables, target_table=target_norm,
            source_tables=source_tables, column_refs=column_refs,
            ambiguous_columns=ambiguous, star_tables=star_tables,
            has_where=has_where, has_returning=has_returning,
            risk=risk, risk_reason=reason,
        )

    def _normalize_table(self, table: "exp.Table") -> str:
        name = table.name
        schema = table.db or self.default_schema
        return f"{schema}.{name}".lower()

    def _cte_names(self, root: "exp.Expression") -> Set[str]:
        """Names introduced by WITH clauses — these are query-local, not real tables."""
        names: Set[str] = set()
        for cte in root.find_all(exp.CTE):
            alias = cte.alias_or_name
            if alias:
                names.add(alias.lower())
        return names

    def _is_cte_ref(self, table: "exp.Table", cte_names: Set[str]) -> bool:
        # A CTE reference has no schema qualifier and matches a WITH name.
        return not table.db and table.name.lower() in cte_names

    def _extract_tables(self, root: "exp.Expression", cte_names: Set[str]) -> List[str]:
        seen: List[str] = []
        for tbl in root.find_all(exp.Table):
            if self._is_cte_ref(tbl, cte_names):
                continue
            norm = self._normalize_table(tbl)
            if norm not in seen:
                seen.append(norm)
        return seen

    def _target_table_node(self, root: "exp.Expression") -> "Optional[exp.Table]":
        """The single table an INSERT/UPDATE/DELETE writes to (None for reads)."""
        if isinstance(root, _READ_ROOTS):
            return None
        this = root.this
        if isinstance(this, exp.Table):
            return this
        if this is not None:
            found = this.find(exp.Table)
            if found is not None:
                return found
        return None

    def _scope_tables(self, scope: "exp.Expression", cte_names: Set[str]) -> Dict[str, str]:
        """alias/name (lower) -> normalized table, for tables owned *directly* by
        this scope (not by a nested sub-select)."""
        amap: Dict[str, str] = {}
        for tbl in scope.find_all(exp.Table):
            if tbl.find_ancestor(*_SCOPES) is not scope:
                continue  # belongs to a nested scope
            if self._is_cte_ref(tbl, cte_names):
                continue  # CTE reference, not a base table
            norm = self._normalize_table(tbl)
            amap[tbl.name.lower()] = norm
            if tbl.alias:
                amap[tbl.alias.lower()] = norm
        return amap

    def _extract_columns(self, root: "exp.Expression", cte_names: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Resolve column references per-scope.

        Returns ``(qualified, ambiguous)`` where ``qualified`` are
        ``schema.table.column`` strings we resolved confidently, and
        ``ambiguous`` are bare column names we could not pin to a table (checked
        conservatively by leaf name against the deny set downstream).
        """
        qualified: Set[str] = set()
        ambiguous: Set[str] = set()
        scope_cache: Dict[int, Dict[str, str]] = {}

        for col in root.find_all(exp.Column):
            if isinstance(col.this, exp.Star):
                continue  # handled in _extract_stars
            scope = col.find_ancestor(*_SCOPES)
            if scope is None:
                amap = self._scope_tables(root, cte_names)
            else:
                key = id(scope)
                if key not in scope_cache:
                    scope_cache[key] = self._scope_tables(scope, cte_names)
                amap = scope_cache[key]

            name = col.name.lower()
            if col.table:
                resolved = amap.get(col.table.lower())
                if resolved:
                    qualified.add(f"{resolved}.{name}")
                else:
                    ambiguous.add(name)  # alias to a derived table / unknown
            else:
                base_tables = {v for v in amap.values()}
                if len(base_tables) == 1:
                    qualified.add(f"{next(iter(base_tables))}.{name}")
                else:
                    ambiguous.add(name)  # unqualified in a multi-source scope
        return qualified, ambiguous

    def _extract_stars(self, root: "exp.Expression", tables: List[str], cte_names: Set[str]) -> Set[str]:
        star_tables: Set[str] = set()
        for star in root.find_all(exp.Star):
            parent = star.parent
            if isinstance(parent, exp.Column) and parent.table:
                scope = parent.find_ancestor(*_SCOPES)
                amap = (self._scope_tables(scope, cte_names) if scope is not None
                        else self._scope_tables(root, cte_names))
                resolved = amap.get(parent.table.lower())
                if resolved:
                    star_tables.add(resolved)
                else:
                    star_tables.update(tables)  # unknown alias — be conservative
            else:
                # Bare '*' exposes whatever tables are in scope; be conservative.
                star_tables.update(tables)
        return star_tables

    def _classify_risk(self, action: Action, has_where: bool, has_star: bool) -> Tuple[Risk, str]:
        if action in (Action.UPDATE, Action.DELETE):
            if not has_where:
                return Risk.HIGH, f"unfiltered {action.value} affects every row"
            return Risk.HIGH, f"{action.value} mutates data"
        if action is Action.INSERT:
            return Risk.MEDIUM, "insert writes new data"
        if not has_where:
            return Risk.MEDIUM, "full-table scan (no WHERE clause)"
        if has_star:
            return Risk.LOW, "wildcard read"
        return Risk.LOW, "scoped read"

    # -- rewrite internals ----------------------------------------------------

    def _equalities(self, predicate: str) -> Dict[str, str]:
        """Extract top-level ``column = literal`` constraints from an AND-ed filter.

        Returns ``{column_lower: literal_sql}``. Predicates that are not a simple
        conjunction of column-equals-literal yield an empty/partial map, which the
        INSERT enforcer treats as unenforceable.
        """
        tree = self._parse_predicate(predicate)
        out: Dict[str, str] = {}

        def visit(node: "exp.Expression") -> None:
            if isinstance(node, exp.And):
                visit(node.left)
                visit(node.right)
            elif isinstance(node, exp.Paren):
                visit(node.this)
            elif isinstance(node, exp.EQ):
                left, right = node.left, node.right
                if isinstance(left, exp.Column) and isinstance(right, exp.Literal):
                    out[left.name.lower()] = right.sql(self.dialect)

        visit(tree)
        return out

    def _parse_predicate(self, predicate: str) -> "exp.Expression":
        try:
            return sqlglot.parse_one(predicate, dialect=self.dialect)
        except Exception as exc:
            raise SqlGuardError(f"row filter is not valid SQL: {predicate!r} ({exc})") from exc

    def _wrap_source(self, node: "exp.Table", predicate: str) -> None:
        """Replace a source table node with ``(SELECT * FROM table WHERE pred) AS alias``."""
        alias_name = node.alias or node.name
        bare = node.copy()
        bare.set("alias", None)
        inner = exp.select("*").from_(bare).where(self._parse_predicate(predicate))
        subquery = exp.Subquery(this=inner, alias=exp.TableAlias(this=exp.to_identifier(alias_name)))
        node.replace(subquery)

    def _inject_target_where(self, root: "exp.Expression", target: "exp.Table", predicate: str) -> None:
        """AND the filter into an UPDATE/DELETE target's WHERE, qualified to the target."""
        cond = self._parse_predicate(predicate)
        alias = target.alias or target.name
        for c in cond.find_all(exp.Column):
            if not c.table:
                c.set("table", exp.to_identifier(alias))
        root.where(cond, append=True, copy=False)

    def _block_scoping_update(self, root: "exp.Update", predicate: str) -> None:
        """Reject an UPDATE that SETs any column used by the row filter."""
        filter_cols = {c.name.lower() for c in self._parse_predicate(predicate).find_all(exp.Column)}
        for assignment in root.args.get("expressions", []) or []:
            left = assignment.this if isinstance(assignment, exp.EQ) else None
            if isinstance(left, exp.Column) and left.name.lower() in filter_cols:
                raise SqlGuardError(
                    f"cannot modify scoping column {left.name!r}; it would move the row "
                    "into another partition/tenant"
                )

    def _enforce_insert(self, root: "exp.Insert", target: "exp.Table", predicate: str) -> None:
        """Pin the scoping column of an INSERT to the principal's context value.

        Only simple equality filters (``col = literal``) can be enforced on an
        INSERT; anything else, or an ``INSERT ... SELECT``, is rejected.
        """
        equalities = self._equalities(predicate)
        if not equalities:
            raise SqlGuardError(
                "this table is row-scoped by a non-equality filter that cannot be "
                "enforced on INSERT"
            )

        payload = root.expression
        if not isinstance(payload, exp.Values):
            raise SqlGuardError(
                "INSERT ... SELECT into a row-scoped table is not supported; "
                "use explicit VALUES so the gate can pin the scope column"
            )

        schema = root.this
        if not isinstance(schema, exp.Schema):
            raise SqlGuardError(
                "INSERT into a row-scoped table must name its columns explicitly"
            )
        col_names = [c.name.lower() for c in schema.expressions]
        tuples = [t for t in payload.expressions if isinstance(t, exp.Tuple)]

        for col, required_sql in equalities.items():
            required = self._parse_predicate(required_sql)
            if col in col_names:
                idx = col_names.index(col)
                for tup in tuples:
                    if idx >= len(tup.expressions):
                        raise SqlGuardError("VALUES row has fewer values than columns")
                    provided = tup.expressions[idx]
                    if not isinstance(provided, exp.Literal) or provided.sql(self.dialect) != required.sql(self.dialect):
                        raise SqlGuardError(
                            f"scoping column {col!r} must be {required.sql(self.dialect)} "
                            "for this principal; forging another value is not allowed"
                        )
            else:
                # Auto-fill the scope column with the principal's value.
                schema.append("expressions", exp.column(col))
                for tup in tuples:
                    tup.append("expressions", required.copy())
