-- NAN-2066: stamp the positive search:sql capability requirement on every
-- successful report run whose artifact was produced from a raw-SQL dashboard
-- panel.
--
-- Authorization must use the frozen run facts, not re-inspect the dashboard at
-- download time: a dashboard owner can remove an SQL panel after a run, but the
-- already-rendered artifact may still contain its result.
--
-- Pre-feature runs are intentionally INCOMPLETE. At read time, an incomplete
-- dashboard-run requirement is treated as requiring search:sql (fail closed);
-- search reports never require search:sql. A fresh successful run stamps a
-- complete true/false decision from the exact authorized dashboard snapshot it
-- executed.

ALTER TABLE report_runs
    ADD COLUMN IF NOT EXISTS requires_search_sql BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE report_runs
    ADD COLUMN IF NOT EXISTS search_sql_requirement_complete BOOLEAN NOT NULL DEFAULT FALSE;
