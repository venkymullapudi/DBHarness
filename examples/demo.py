"""End-to-end demonstration of the DBHarness enforcement pipeline.

Runs entirely in-process against an in-memory SQLite database — no MCP transport,
no external DB — so you can watch each control fire. Run it with:

    PYTHONPATH=src python examples/demo.py
"""

from __future__ import annotations

import asyncio
import json
import os

from dbharness.config import Settings, build_gate

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def show(title: str, result) -> None:
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    print(f"\n=== {title} ===")
    print(json.dumps(payload, indent=2, default=str))


async def main() -> None:
    settings = Settings(
        policy_path=os.path.join(ROOT, "policies", "example.yaml"),
        backend="sqlite",
        dsn=":memory:",
        audit_path=os.path.join(HERE, "demo-audit.jsonl"),
        api_key=None,
        seed_sql=os.path.join(HERE, "seed.sql"),
    )
    # Fresh audit log each run.
    if os.path.exists(settings.audit_path):
        os.remove(settings.audit_path)

    gate = build_gate(settings)
    await gate.executor.connect()
    with open(settings.seed_sql, encoding="utf-8") as fh:
        await gate.executor.run_script(fh.read())

    support = gate.authenticate("support-dev-key")
    billing = gate.authenticate("billing-dev-key")
    admin = gate.authenticate("admin-dev-key")

    print("DBHarness demo — ITSM help-desk over a shared multi-tenant DB\n")
    print("support-bot can see only these tables:",
          await gate.list_tables(support))

    # 1. Row scoping: support-bot sees ONLY its tenant's tickets, even asking for all.
    show("support-bot: SELECT * FROM tickets  (row filter injected → acme only)",
         await gate.handle_sql(support, "SELECT id, tenant_id, subject FROM tickets", "read"))

    # 2. Column redaction: reading the SSN is denied.
    show("support-bot: SELECT ssn FROM customers  (denied — redacted column)",
         await gate.handle_sql(support, "SELECT id, ssn FROM customers", "read"))

    # 3. Wildcard over a table with a redacted column is blocked.
    show("support-bot: SELECT * FROM customers  (blocked — '*' could leak ssn)",
         await gate.handle_sql(support, "SELECT * FROM customers", "read"))

    # 4. Explicit safe columns are allowed, still tenant-scoped.
    show("support-bot: SELECT id, name FROM customers  (allowed, acme only)",
         await gate.handle_sql(support, "SELECT id, name FROM customers", "read"))

    # 5. No DELETE grant → denied by default.
    show("support-bot: DELETE FROM tickets WHERE id=1  (denied — no grant)",
         await gate.handle_sql(support, "DELETE FROM tickets WHERE id=1", "write"))

    # 6. Scoped UPDATE is allowed; the gate ANDs the tenant filter in.
    show("support-bot: UPDATE tickets SET status='closed' WHERE id=1  (scoped write)",
         await gate.handle_sql(support, "UPDATE tickets SET status='closed' WHERE id=1", "write"))

    # 7. Privileged write → held for approval, not executed.
    pending = await gate.handle_sql(
        billing, "UPDATE customers SET plan='enterprise' WHERE id=1", "write")
    show("billing-bot: UPDATE customers ...  (privileged → pending approval)", pending)

    # 8. Operator approves, then the agent runs exactly what was approved.
    gate.pam.decide(pending.approval_id, approve=True, approver=admin.id)
    show("admin approves; billing-bot: run_approved(...)  (now executes)",
         await gate.run_approved(billing, pending.approval_id))

    # 9. The audit log has the whole story.
    print("\n=== audit log (tail) ===")
    for rec in gate.audit.tail(20):
        print(f"  [{rec['outcome']:>16}] {rec['principal_id']:<12} "
              f"{rec['action']:<8} {rec.get('reason','') or rec.get('effective_sql','')}")

    await gate.executor.close()


if __name__ == "__main__":
    asyncio.run(main())
