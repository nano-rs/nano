-- F-31 (red-team July 2026): historical report artifacts must honour a source-
-- access revocation applied AFTER the run was stored.
--
-- Stored artifacts are frozen byte blobs with no per-row source attribution, so
-- a source-scoped viewer cannot be row-filtered at download time. Instead we
-- stamp each run with the DISTINCT source_type manifest of the artifacts it
-- produced, plus a completeness flag, and gate downloads on it.
--
-- INVERTED semantics vs alerts.source_types (migration 246): for a report, an
-- EMPTY manifest with source_types_complete = FALSE must DENY any restricted
-- requester — the bytes may contain anything. That is exactly the default every
-- pre-feature run carries ('{}' + FALSE), so already-stored runs are
-- deny-by-default for source-scoped users until a fresh run stamps a trustworthy
-- manifest. Only a run whose manifest is COMPLETE and disjoint from a requester's
-- deny set is safe to serve.
--
-- No in-migration backfill: back-filling '{}' + complete would be a fail-OPEN
-- lie (we cannot reconstruct provenance of bytes already written).

ALTER TABLE report_runs
    ADD COLUMN IF NOT EXISTS source_types TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE report_runs
    ADD COLUMN IF NOT EXISTS source_types_complete BOOLEAN NOT NULL DEFAULT FALSE;
