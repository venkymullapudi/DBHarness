-- PostgreSQL Row-Level Security — defense in depth for DBHarness.
--
-- The gate already rewrites every statement to enforce tenant scoping. RLS adds
-- a SECOND, independent enforcement layer *inside the database*: even if a gate
-- bug or a future code path let an unfiltered query through, PostgreSQL itself
-- refuses to return or write another tenant's rows.
--
-- How it fits together:
--   * The gate connects to Postgres as the least-privilege role `dbharness_agent`
--     (NOT a superuser, NOT BYPASSRLS — both would defeat RLS).
--   * On every statement the gate sets a transaction-local GUC
--     `dbharness.tenant_id` from the calling principal's context
--     (see Gate._session_for / PostgresExecutor._apply_session).
--   * The policies below constrain every row to that GUC. `current_setting(...,
--     true)` returns NULL when the GUC is unset, so an un-scoped connection sees
--     NOTHING — fail closed.
--
-- Apply after the schema exists (e.g. after examples/seed_pg.sql):
--   psql "$DSN" -f postgres/rls.sql
--
-- NOTE: principals with no tenant (e.g. a break-glass admin) cannot use this
-- connection — route them through a separate role that holds BYPASSRLS, or add
-- an explicit policy for them. Do not give the agent role BYPASSRLS.

-- 1. Least-privilege login role the gate connects as. Change the password.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbharness_agent') THEN
    CREATE ROLE dbharness_agent LOGIN PASSWORD 'agentpw';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO dbharness_agent;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dbharness_agent;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dbharness_agent;

-- 2. Enable + FORCE RLS and install a tenant-isolation policy on each scoped
--    table. FORCE ensures the policy applies even to a table's owner.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['customers', 'tickets', 'ticket_comments', 'invoices']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = current_setting(''dbharness.tenant_id'', true)) '
      'WITH CHECK (tenant_id = current_setting(''dbharness.tenant_id'', true))',
      t
    );
  END LOOP;
END
$$;
