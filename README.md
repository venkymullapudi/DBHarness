# DBHarness

### Interact with your database.

**Ask in plain English — "show the open tickets", "close ticket 1" — and let AI agents read and write your database without ever getting direct, unchecked access.**

<p align="center">
  <img src="docs/demo.gif" alt="DBHarness: asking a database in plain English. A read returns only the caller's own tenant, PII columns are hidden automatically, and a write asks for confirmation before it runs — all enforced by the gate, no SQL required." width="820">
</p>

## What is this?

AI agents are good at deciding *what* to do, but you can't fully trust *how* they
do it — they hallucinate, and they can be steered by prompt injection. Handing one
a live database connection is risky.

DBHarness is the safety layer in between. An agent connects to the gate (over
[MCP](https://modelcontextprotocol.io)) and asks it to run SQL. The **gate**, not
the agent, decides what's allowed, rewrites the query so it can't step outside the
rules, asks a human to approve anything dangerous, runs it with credentials the
agent never sees, and records everything.

> **One rule drives the whole design: the gate never trusts the agent.** Every
> guarantee is enforced at the gate, deterministically. The agent only ever sees a
> constrained surface and never holds the database credentials.

In plain terms, an agent can only:

- read and write the tables, columns, and rows its **role** allows — down to a
  single tenant's data;
- **never** see redacted columns (PII stays hidden), even through clever nested
  queries;
- **never** run a destructive or privileged statement without a **human's OK**;

…and every attempt — allowed or denied — is written to an audit log.

DBHarness is a **platform**: point it at a database, write a policy, and build your
agent-driven automation (ITSM, CRM, ERP, or anything else) on top. Those
application tools are yours to build — DBHarness is the gate underneath them.

---

## How it works

Every request an agent makes flows through one deterministic pipeline:

```
authenticate → analyze (SQL AST) → decide (RBAC) → rewrite (enforce)
            → risk / approval (PAM) → execute (vaulted creds) → audit
```

| Stage | Component | What it guarantees |
|-------|-----------|--------------------|
| **Authenticate** | `gate.authenticate` | Each agent is a first-class principal with its own key; DB creds never leave the gate. |
| **Analyze** | `dbharness.sql` (sqlglot) | Parses a **real AST**, not regex. One statement only; DDL/DELETE-all/multi-statement blocked up front. |
| **Decide** | `dbharness.policy` | Deny-by-default RBAC scoped to schema → table → **column** → **row**. |
| **Rewrite** | `dbharness.sql` | Injects tenant row filters and blocks redacted columns *into the statement*, so a compromised agent physically cannot exceed its grant. |
| **PAM** | `dbharness.pam` | Just-in-time role elevation (time-boxed) and human-approval gating for privileged writes. |
| **Execute** | `dbharness.db` | Runs the rewritten statement with pooled, vaulted credentials. |
| **Audit** | `dbharness.audit` | Append-only record of *every* request — the "session recording" for agents. |

## Quick start (zero infra)

The demo runs entirely in-process against in-memory SQLite — no database to set up.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install sqlglot pyyaml aiosqlite
PYTHONPATH=src python examples/demo.py
```

You'll watch each control fire: tenant row-scoping, PII column redaction, a
blocked `SELECT *`, deny-by-default, an approval-gated privileged write, and the
audit trail.

## Run the tests

```bash
pip install sqlglot pyyaml aiosqlite pytest pytest-asyncio
PYTHONPATH=src python -m pytest -q
```

61 unit + adversarial tests run against SQLite with no infra. The 14
live-Postgres integration tests skip automatically unless a database is
configured (see below).

### Integration tests against real PostgreSQL

The same enforcement guarantees are verified against a live Postgres server —
where the rewrites meet the real query planner and Postgres-only threats (a
data-modifying CTE genuinely writes; `pg_read_file` genuinely reads the disk)
are actually executable. One command spins up a Dockerized Postgres, runs the
suite, and tears it down:

```bash
pip install -e ".[dev,postgres]"
scripts/run_pg_integration.sh
```

Or point the suite at any Postgres yourself:

```bash
docker compose up -d
DBHARNESS_TEST_PG_DSN=postgresql://postgres:dbharness@localhost:55432/dbharness \
  PYTHONPATH=src python -m pytest tests/integration -v
docker compose down
```

One integration test is worth calling out: it runs a data-modifying CTE
*unguarded* to prove Postgres really deletes the row, then runs the identical
statement *through the gate* to prove it is refused before reaching the database.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the unit suite
**and** the live-Postgres integration suite (against a `postgres:16` service
container) on Python 3.10, 3.11, and 3.12 for every push and PR.

### Defense in depth: PostgreSQL Row-Level Security

The gate rewrites every statement to enforce scoping, but you can add a *second,
independent* enforcement layer inside the database so that even a gate bug can't
cross a tenant boundary. [`postgres/rls.sql`](postgres/rls.sql) creates a
least-privilege role and tenant-isolation policies; the gate sets a
transaction-local `dbharness.tenant_id` GUC from each principal's context on every
statement, and the policies bind every row to it (unset → zero rows, fail
closed).

```bash
# after seeding the schema, as a superuser:
psql "$DSN" -f postgres/rls.sql
# then run the gate connected as the restricted role:
export DBHARNESS_DSN="postgresql://dbharness_agent:agentpw@localhost:5432/appdb"
```

The RLS tests ([`tests/integration/test_pg_rls.py`](tests/integration/test_pg_rls.py))
prove a *raw, unfiltered* query through the restricted role still returns only
the session tenant's rows, and that a forged cross-tenant `INSERT` is rejected by
the database itself.

## Run the MCP server

The MCP transport needs **Python ≥ 3.10** (the `mcp` SDK's floor). Install the
`server` extra, then point an MCP client at it over stdio:

```bash
pip install -e ".[server]"          # add ".[postgres]" for PostgreSQL
export DBHARNESS_POLICY=policies/example.yaml
export DBHARNESS_API_KEY=support-dev-key      # identifies the connecting agent
export DBHARNESS_SEED_SQL=examples/seed.sql   # optional demo seed (sqlite)
dbharness                                       # serves MCP over stdio
```

Example MCP client config (Claude Desktop / any MCP host):

```json
{
  "mcpServers": {
    "dbharness": {
      "command": "dbharness",
      "env": {
        "DBHARNESS_POLICY": "policies/example.yaml",
        "DBHARNESS_API_KEY": "support-dev-key",
        "DBHARNESS_SEED_SQL": "examples/seed.sql"
      }
    }
  }
}
```

### Point it at PostgreSQL

```bash
pip install -e ".[server,postgres]"
export DBHARNESS_BACKEND=postgres
export DBHARNESS_DSN="postgresql://gate_user:secret@localhost:5432/appdb"
export DBHARNESS_POLICY=policies/example.yaml
export DBHARNESS_API_KEY=support-dev-key
dbharness
```

The DSN's credentials are the *gate's* — agents authenticate with their own
`DBHARNESS_API_KEY` and never see the DSN.

## Command-line tools

The `dbharness` command wraps the platform:

```bash
dbharness serve                       # run the MCP server (default; reads DBHARNESS_* env)
dbharness policy validate policies/example.yaml   # lint a policy, print a summary
# dry-run: what WOULD the gate do with this statement? (never touches a DB)
dbharness explain --policy policies/example.yaml --principal support-bot \
  --sql "SELECT * FROM customers" --dialect postgres
```

`explain` prints the decision, the rewritten (enforced) SQL, injected row
filters, redacted columns, and whether approval is required — so you can review a
policy change before it ships. Its exit code is non-zero when the statement would
be denied, which makes it usable as a CI gate on policy changes.

## Platform capabilities

- **Backends** behind one `Executor` interface: SQLite, PostgreSQL (first-class,
  integration-tested), MySQL/MariaDB (adapter; construction + dialect tested,
  live integration needs a server). Selected by `DBHARNESS_BACKEND`.
- **Secrets** ([`secrets.py`](src/dbharness/secrets.py)): DSNs/keys come from a
  reference (`env:`, `file:`, or a registered provider for Vault / AWS / GCP)
  instead of living in config.
- **Observability** ([`observability.py`](src/dbharness/observability.py)): the
  gate emits a structured event per decision (`denied` / `pending_approval` /
  `executed` / `error`). Point the `Observer` at metrics/tracing;
  `InMemoryMetrics` and `LoggingObserver` ship in the box.
- **Pluggable state**: `PamStore` (approvals + elevation) and `AuditSink` seams,
  with in-process/file defaults, so multi-node PAM and a WORM audit sink are
  drop-in replacements.

## Agent-facing MCP tools

| Tool | Purpose |
|------|---------|
| `whoami` | The agent's identity, roles (incl. active elevation), and context. |
| `list_tables` | Only the tables the agent may read (policy-filtered). |
| `describe_table` | Columns of a permitted table. |
| `query(sql)` | Run a SELECT. Row filters injected, redacted columns blocked. |
| `execute(sql)` | Run an INSERT/UPDATE/DELETE. Risky writes → `pending_approval`. |
| `run_approved(approval_id)` | Execute a statement an operator approved — exactly as approved. |

**Two ways for an agent to talk to the gate.** An agent can send **raw SQL**
(`query`/`execute`) *or* use the **structured tools** below — typed operations
that the gate compiles to SQL deterministically, so the agent never authors SQL
text. Either way the request runs through the *same* enforcement pipeline.

| Structured tool | Purpose |
|------|---------|
| `find(table, filters, columns, order_by, limit)` | Read rows without writing SQL. |
| `insert(table, values)` | Insert a row (scope column pinned by the gate). |
| `update(table, values, filters, all)` | Update rows (filters required unless `all=True`). |
| `delete(table, filters, all)` | Delete rows (filters required unless `all=True`). |

`filters` is `{column: value}` (equality) or a list of
`{"column","op","value"}` with `op` in
`eq/ne/lt/lte/gt/gte/in/nin/like/ilike/is_null/not_null`. Identifiers are
validated and values are bound literals, so there's no SQL-injection surface in
this layer — and `update`/`delete` refuse to run unfiltered unless you pass
`all=True`.

### Natural language (`ask`)

There's also an `ask(text)` tool for plain English — "show the open tickets",
"how many customers", "set status to closed on tickets where id is 1". It works
the safe way:

```
text → translator → a structured/SQL candidate → the SAME gate pipeline
```

The translator is **untrusted**: a mistranslation or a prompt-injected sentence
can never exceed the principal's grant, because the gate still enforces RBAC, row
filters, redaction and approval on the compiled statement. The translator is also
only shown the schema the principal may read, so it stays in scope. **Reads run
immediately; writes return a preview of the exact compiled statement and require
`confirm=true`** — words never silently mutate data. Two translators ship: a
deterministic offline one (default, no API key) and an optional LLM-backed one
(`DBHARNESS_NL=llm`) that falls back to the deterministic one when unavailable.

Operator tools (require the `admin` role): `list_pending_approvals`,
`decide_approval`, `elevate`, `audit_tail`.

## Writing a policy

Policy is declarative YAML — reviewable and version-controlled like code. See
[`policies/example.yaml`](policies/example.yaml). A role grants actions on
resources, optionally with a `row_filter` (with `{ctx.key}` placeholders drawn
from the principal's context), `deny_columns`, and `require_approval`:

```yaml
roles:
  support_agent:
    permissions:
      - effect: allow
        actions: [select]
        resources: [public.customers]
        row_filter: "tenant_id = {ctx.tenant_id}"   # ANDed into every query
        deny_columns: [ssn]                          # redacted; SELECT * blocked
      - effect: allow
        actions: [update]
        resources: [public.tickets]
        row_filter: "tenant_id = {ctx.tenant_id}"

principals:
  - id: support-bot
    api_key_env: SUPPORT_BOT_KEY    # prefer env over inline in production
    roles: [support_agent]
    context: { tenant_id: acme }
```

## Security model

The enforcement core is covered by an adversarial test suite
([`tests/test_security.py`](tests/test_security.py)) that encodes the bypasses a
malicious or prompt-injected agent might attempt. Each of the following is
enforced and regression-tested:

**Statement shape (fail closed).** Exactly one statement; only
SELECT/UNION/INSERT/UPDATE/DELETE at the root. Blocked: stacked statements
(`…; DROP …`), all DDL, `SELECT … INTO`, `EXPLAIN`, and — critically —
**data-modifying CTEs** (`WITH x AS (DELETE … RETURNING *) SELECT …`), which are
a SELECT that writes. A configurable **dangerous-function denylist** rejects
`pg_read_file`, `lo_import`, `dblink`, `pg_sleep`, `load_extension`,
`xp_cmdshell`, and friends anywhere in the tree.

**Row scoping that can't be escaped.** Each filtered table is replaced in the
AST by a filtered derived table — `tickets` → `(SELECT * FROM tickets WHERE
tenant_id='acme') AS tickets`. Because the filter lives *inside* the table
reference, it binds correctly through **subqueries, CTEs, JOINs, self-joins, and
UNION branches** — not just top-level `WHERE`. UPDATE/DELETE targets get a
qualified, correctly-parenthesized `WHERE` predicate (an `OR` in the agent's
clause cannot lift the filter). Writes cannot cross tenants: an `INSERT` has its
scope column pinned to the principal's context (auto-filled if omitted, rejected
if forged, even across multi-row `VALUES`), and an `UPDATE` may not `SET` a
scoping column.

**Column redaction that can't be smuggled.** Columns are resolved **per query
scope**, so a redacted column is caught through aliases, expressions, aggregates,
`ORDER BY`, `CASE`, `RETURNING`, and scalar/`WHERE` subqueries — including the
tricky case where the redacted column hides in a subquery over a *different*
outer table. `*` and `t.*` over any table with a redacted column are blocked, and
`RETURNING` is treated as a read subject to SELECT column permissions.

**Access control.** Deny-by-default RBAC scoped to schema → table → column → row;
every table in a statement must be granted (source tables need SELECT, the write
target needs the mutating action); explicit `deny` beats any allow; fail-closed
on an unresolved row-filter context key.

**PAM & accountability.** Approval-gated privileged and unfiltered writes, bound
to the *exact* rewritten statement (no approve-then-swap, no replay, no
cross-principal consume); JIT time-boxed role elevation; append-only audit of
every request; agents authenticate with their own key and never hold DB
credentials.

### Hardening to do before production

- **PAM/approval/elevation state is in-process** — a `PamStore` seam is provided
  (`InMemoryPamStore` default); implement it against Redis/a DB table for a
  multi-node deployment.
- **The audit log is a local JSONL file** — an `AuditSink` seam is provided
  (`FileAuditSink` default); point it at an append-only/WORM sink (object-lock
  bucket, WORM table, log pipeline).
- **Row-level security is available** as a defense-in-depth layer
  ([`postgres/rls.sql`](postgres/rls.sql), tested) — enable it in production and
  connect the gate as the restricted `dbharness_agent` role. Principals without a
  tenant (break-glass admin) need a separate `BYPASSRLS` connection.
- **One principal per MCP connection** (via `DBHARNESS_API_KEY`) — per-call
  identity would need transport-level auth.
- **Quoted, case-sensitive identifiers** are normalized to lower case; if you
  rely on case-sensitive table/column names, add schema-aware qualification
  (sqlglot's `qualify` optimizer with a real schema).
- INSERT scope-pinning supports **equality filters** (`col = value`); a
  non-equality row filter on an INSERT target is rejected rather than guessed.

## Project layout

```
src/dbharness/
  policy/        # RBAC model, YAML loader, decision engine
  sql/           # AST-based analyzer + rewriter (sqlglot)
  pam.py         # JIT elevation + approval workflow (+ pluggable PamStore)
  audit.py       # append-only audit log (+ pluggable AuditSink)
  db.py          # pluggable executors (SQLite, PostgreSQL, MySQL, Null)
  nl.py            # natural-language -> structured request (RuleBased + optional LLM)
  querybuilder.py  # structured find/insert/update/delete -> SQL (no raw SQL from agents)
  secrets.py     # secret-reference resolution (env/file/custom providers)
  observability.py # per-decision event emitter (metrics/tracing seam)
  gate.py        # the enforcement pipeline (composition root) + explain()
  config.py      # build a Gate from env
  server.py      # MCP server (agent-facing surface)
  cli.py         # `dbharness` CLI: serve / policy validate / explain
policies/example.yaml
examples/demo.py, examples/seed.sql, examples/seed_pg.sql
tests/               # unit + adversarial (SQLite)
tests/integration/   # live-PostgreSQL suite: gate + RLS (skipped without a DSN)
postgres/rls.sql     # optional row-level-security defense-in-depth
scripts/run_pg_integration.sh, docker-compose.yml
.github/workflows/ci.yml
```

## License

Apache-2.0.
