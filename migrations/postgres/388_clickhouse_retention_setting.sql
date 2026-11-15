-- SPDX-License-Identifier: AGPL-3.0-or-later
-- ============================================================================
-- Migration 388: ClickHouse event retention as a recorded setting (NAN-5449)
-- ============================================================================
-- The event TTL lives in the ClickHouse DDL. These columns record who set it
-- last, so a deployment value (`NANO_RETENTION_DAYS`, applied by the
-- migrator) and a value set in Settings -> Storage do not overwrite each
-- other silently:
--
--   clickhouse_retention_days         the TTL nano last applied (NULL = never
--                                     changed from the shipped DDL default)
--   clickhouse_retention_source       'deployment' or 'ui'
--   clickhouse_retention_env_applied  the NANO_RETENTION_DAYS value the
--                                     migrator last applied. The migrator
--                                     applies the env value only when it
--                                     differs from this, so a restart with an
--                                     unchanged .env keeps a UI change.
--
-- Forward-only, idempotent, no data backfill.
-- ============================================================================

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS clickhouse_retention_days integer,
  ADD COLUMN IF NOT EXISTS clickhouse_retention_source text,
  ADD COLUMN IF NOT EXISTS clickhouse_retention_env_applied integer;
