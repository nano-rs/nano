-- NAN-5032: platform-owned source types cannot be forged through ingest.
--
-- The audit page reads `source_type = 'audit'` from `logs`, and tuning / risk
-- read `source_type = 'findings'`. Every multiplex ingest lane keeps the
-- sender-declared type, so a forwarder holding the install token could insert
-- rows the audit page showed as genuine audit entries.
--
-- The generated Vector pipeline now rewrites these values at its storage
-- boundary (`reserved_source_type_guard_vrl!`). This is the database-side
-- backstop that does not depend on the pipeline having been regenerated:
-- `logs_ingest_mv` (migration 189) is the ONLY bridge from Vector's write-only
-- credential into `logs`, so rewriting here covers every Vector lane on every
-- deployment as soon as this migration runs. The audit emitter and the
-- findings writer insert into `logs` directly as the platform user and never
-- pass this view, so genuine records are untouched.
--
-- Keep this list identical to `nanosiem_core::auth::reserved_source_types::
-- ENFORCED` and `SPOOF_MARKER` (a unit test compares them).
--
-- MODIFY QUERY (not DROP + CREATE) so there is no window in which Vector
-- inserts land nowhere; it takes the SELECT directly, no `AS` (NAN-1727). The
-- cluster transform adds `ON CLUSTER`. The SQL SECURITY DEFINER contract from
-- 189 is re-asserted afterwards so the bridge keeps executing as its owner.

ALTER TABLE nanosiem.logs_ingest_mv /* nano:skip-if-unknown-table */
MODIFY QUERY SELECT * REPLACE (
    if(lower(source_type) IN ('audit', 'findings'), 'reserved_spoof', source_type) AS source_type
) FROM nanosiem.logs_ingest;

ALTER TABLE nanosiem.logs_ingest_mv /* nano:skip-if-unknown-table */
MODIFY SQL SECURITY DEFINER DEFINER = CURRENT_USER;
