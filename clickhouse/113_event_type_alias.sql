-- NAN-659: Add `event_type` as a read alias for the `action` UDM column.
--
-- Phase 1 of the action -> event_type rename. The on-disk column stays `action`
-- (so existing data, the idx_action set-index, and INSERT paths are untouched);
-- `event_type` is a query-time rewrite that resolves to `action`.
--
-- Queries against `event_type` get the full speed of `idx_action` and PREWHERE
-- because the alias is substituted at query-plan time. The alias is read-only,
-- so writes still target the `action` column (handled by the ingestion layer).
--
-- Phase 2 (separate migration, later) will RENAME COLUMN action -> event_type
-- once the parser fleet has migrated, and add `action` as the reverse alias.

ALTER TABLE nanosiem.logs ADD COLUMN IF NOT EXISTS `event_type` LowCardinality(String) ALIAS action;
