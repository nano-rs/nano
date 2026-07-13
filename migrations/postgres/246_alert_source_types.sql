-- Detection-derived surface scoping — alert source_type stamping (NAN-1800 / epic NAN-1789)
--
-- Every alert row records the DISTINCT (normalized: trimmed + lowercased)
-- `source_type` values of its matched events so the read side can enforce
-- per-source RBAC with a simple array-overlap test against the viewer's deny
-- set (`NOT (source_types && $deny)`).
--
-- Semantics:
--   * '{}' (empty array) = pre-feature row OR a producer whose events carry no
--     source_type (observability / risk-notable alerts) = VISIBLE to everyone
--     (back-compat; those alerts are not source-derived).
--   * Aggregate detection rules (stats/timechart/top/rare) collapse the raw
--     stream, so the detection engine stamps the window's distinct source
--     types onto the matched events (`_nano_source_types`) before insert; the
--     derivation in `AlertRepository::create_alert` picks up both forms.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS source_types TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN alerts.source_types IS
    'Distinct normalized source_type values of the matched events; empty = pre-feature or non-source-derived producer = visible to all (NAN-1800)';

-- Overlap (&&) lookups for the read-side deny filter.
CREATE INDEX IF NOT EXISTS idx_alerts_source_types
    ON alerts USING GIN (source_types);
