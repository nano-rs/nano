-- NAN-1622: Retire the legacy PostgreSQL `audit_logs` subsystem.
--
-- ClickHouse (`source_type='audit'`, written by the in-process AuditEmitter) is
-- the audit system-of-record: it backs the audit UI, the audit export, and the
-- per-API-key usage sparkline (migrated off PG in this change). The PG
-- `audit_logs` table was a write-mostly legacy stub — its only remaining reader
-- was the sparkline, and every auth-layer mutation/denial it recorded is also
-- emitted to ClickHouse. The application-level retention sweep and all PG audit
-- writers are removed in the same change, so the table is now unreferenced.
DROP TABLE IF EXISTS audit_logs;
