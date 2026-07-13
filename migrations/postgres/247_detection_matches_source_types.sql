-- Detection-derived surface scoping — detection_matches source_type stamping
-- (NAN-1808 / epic NAN-1789)
--
-- detection_matches stores the FULL matched_events payload (the same raw rows
-- that back alerts), but it is a SIBLING surface: the alerts.source_types
-- column (migration 246) does not cover it, so a per-source-restricted viewer
-- could read denied-source events through /api/rules/{id}/matches. Stamp each
-- match row with the DISTINCT (normalized: trimmed + lowercased) `source_type`
-- values of its matched events so the read side can enforce per-source RBAC
-- with the same array-overlap test used for alerts
-- (`NOT (source_types && $deny)`).
--
-- Semantics (identical to alerts.source_types):
--   * '{}' (empty array) = pre-feature row OR a producer whose events carry no
--     source_type (e.g. retro-hunt indicator summaries) = VISIBLE to everyone
--     (back-compat; those matches are not source-derived).
--   * Aggregate detection rules (stats/timechart/top/rare) collapse the raw
--     stream, so the detection engine stamps the window's distinct source
--     types onto the matched events (`_nano_source_types`) before insert; the
--     derivation in `store_detection_match` picks up both forms.

ALTER TABLE detection_matches
    ADD COLUMN IF NOT EXISTS source_types TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN detection_matches.source_types IS
    'Distinct normalized source_type values of the matched events; empty = pre-feature or non-source-derived producer = visible to all (NAN-1808)';

-- Overlap (&&) lookups for the read-side deny filter.
CREATE INDEX IF NOT EXISTS idx_detection_matches_source_types
    ON detection_matches USING GIN (source_types);
