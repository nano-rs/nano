-- NAN-1075: capture search mode + time window on saved searches.
--
-- Without these, loading a saved Free + Last 12h search runs in
-- whatever mode + window the analyst happens to have selected at the
-- moment of click — usually wrong.
--
-- Existing rows backfill to ('structured', '24h'), matching the v1
-- defaults the page picks when nothing is set. CHECK on `mode`
-- prevents new values from sneaking in before the parser learns to
-- handle them.

ALTER TABLE case_saved_searches
    ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'structured',
    ADD COLUMN IF NOT EXISTS time_window TEXT NOT NULL DEFAULT '24h';

ALTER TABLE case_saved_searches
    DROP CONSTRAINT IF EXISTS case_saved_searches_mode_check;
ALTER TABLE case_saved_searches
    ADD CONSTRAINT case_saved_searches_mode_check
    CHECK (mode IN ('structured', 'free'));
