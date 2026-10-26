"""DBHarness — an RBAC + PAM enforcement gateway between AI agents and a database.

The gate is the trust boundary. Agents never receive DB credentials and never
run raw SQL directly against the database: every request is authenticated to a
principal, decided by the policy engine, rewritten to physically enforce the
grant (row filters + column redaction), risk-classified, optionally held for
human approval, executed with vaulted credentials, and recorded in an immutable
audit log.
"""

__version__ = "0.1.0"
