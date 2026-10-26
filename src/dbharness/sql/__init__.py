"""SQL analysis + rewriting layer, built on a real AST (sqlglot), never regex.

Regex-based SQL "sanitizing" is a well-known failure mode: comments, string
literals, nested queries and dialect quirks all defeat it. DBHarness parses the
statement into an abstract syntax tree, reasons over the tree, and rewrites the
tree — so the enforcement matches what the database will actually execute.
"""

from dbharness.sql.guard import (
    AnalyzedStatement,
    Risk,
    SqlGuard,
    SqlGuardError,
)

__all__ = ["AnalyzedStatement", "Risk", "SqlGuard", "SqlGuardError"]
