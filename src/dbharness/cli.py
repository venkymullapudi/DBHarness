"""DBHarness command-line interface.

    dbharness serve                 # run the MCP server (default when no subcommand)
    dbharness policy validate PATH  # load & lint a policy file, report a summary
    dbharness explain ...           # dry-run a statement: what WOULD the gate do?

``explain`` is a security-review tool: it shows the decision, the rewritten
(enforced) SQL, injected row filters, redacted columns, and whether approval is
required — without connecting to or touching any database.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from dbharness.audit import AuditLog, NullAuditSink
from dbharness.db import NullExecutor
from dbharness.gate import Gate
from dbharness.policy.loader import PolicyError, load_policy


def _cmd_serve(_args: argparse.Namespace) -> int:
    from dbharness.server import main as serve_main

    serve_main()
    return 0


def _cmd_policy_validate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.path)
    except (PolicyError, OSError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    n_perms = sum(len(r.permissions) for r in policy.roles.values())
    print(f"OK: {args.path}")
    print(f"  principals: {len(policy.principals)} "
          f"({', '.join(sorted(policy.principals)) or 'none'})")
    print(f"  roles:      {len(policy.roles)} "
          f"({', '.join(sorted(policy.roles)) or 'none'})")
    print(f"  permissions: {n_perms}")
    for pid, p in sorted(policy.principals.items()):
        print(f"  - {pid}: roles={p.roles or []} context={p.context or {}}")
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        print(f"could not load policy: {exc}", file=sys.stderr)
        return 2

    principal = policy.principals.get(args.principal)
    if principal is None:
        print(f"unknown principal {args.principal!r}; known: "
              f"{', '.join(sorted(policy.principals))}", file=sys.stderr)
        return 2

    sql = args.sql if args.sql is not None else sys.stdin.read()
    if not sql.strip():
        print("no SQL provided (pass --sql or pipe it on stdin)", file=sys.stderr)
        return 2

    gate = Gate(
        policy=policy,
        executor=NullExecutor(dialect=args.dialect, default_schema=args.default_schema),
        audit=AuditLog(sink=NullAuditSink()),
    )
    result = gate.explain(principal, sql, mode=args.mode)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("allowed") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dbharness", description=__doc__)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="run the MCP server (reads DBHARNESS_* env)")

    pol = sub.add_parser("policy", help="policy tooling")
    pol_sub = pol.add_subparsers(dest="policy_command")
    val = pol_sub.add_parser("validate", help="load and lint a policy file")
    val.add_argument("path", help="path to the policy YAML")

    exp = sub.add_parser("explain", help="dry-run a statement against a policy (no DB)")
    exp.add_argument("--policy", required=True, help="path to the policy YAML")
    exp.add_argument("--principal", required=True, help="principal id to evaluate as")
    exp.add_argument("--sql", default=None, help="the SQL (or pipe it on stdin)")
    exp.add_argument("--mode", choices=["read", "write"], default="read")
    exp.add_argument("--dialect", default="postgres",
                     help="sqlglot dialect (postgres/mysql/sqlite)")
    exp.add_argument("--default-schema", default="public")
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Default to `serve` so the documented MCP config (command: "dbharness") works.
    if not argv:
        argv = ["serve"]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        raise SystemExit(_cmd_serve(args))
    if args.command == "policy":
        if getattr(args, "policy_command", None) == "validate":
            raise SystemExit(_cmd_policy_validate(args))
        parser.parse_args(["policy", "--help"])
    if args.command == "explain":
        raise SystemExit(_cmd_explain(args))
    parser.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
