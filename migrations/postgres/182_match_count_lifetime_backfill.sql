-- NAN-869: backfill `detection_rules.match_count` to be the true lifetime
-- match counter across both Alerting and Live (bake-in) modes.
--
-- Until this migration, Live-mode executions only incremented
-- `live_match_count`, so the UI's "Matches: N" chip and "TOTAL MATCHES"
-- panel read 0 for any rule that had never run in Alerting mode. The
-- two columns are disjoint (no code path folds one into the other —
-- verified across lifecycle.rs mode transitions), so this one-shot add
-- is exact, not a double-count. Both columns are NOT NULL DEFAULT 0
-- (001_init_postgres.sql:663-665), so no COALESCE is needed.
UPDATE detection_rules
SET match_count = match_count + live_match_count
WHERE live_match_count > 0;
