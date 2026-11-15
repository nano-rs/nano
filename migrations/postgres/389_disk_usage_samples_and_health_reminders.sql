-- SPDX-License-Identifier: AGPL-3.0-or-later
-- ============================================================================
-- Migration 389: disk usage samples and repeating health reminders (NAN-5450)
-- ============================================================================
-- disk_usage_samples: one row per measured volume every health-scheduler
-- cycle (jobs leader, every 5 minutes), pruned after 24 hours. Every app host
-- fits the disk growth forecast ("about N hours until full") from it, so the
-- banner, /health/detailed and SIEM Health agree.
--
-- system_health_events.last_reminded_at: when an imminent condition last
-- re-notified the configured channels. The hourly repeat claims its slot with
-- one conditional UPDATE on this column, so two hosts never both send it.
--
-- (Numbered 389: 386 is the alert-cooldown key on main, 387 is NAN-5443
-- (#9630) and 388 is NAN-5449 (#9628).) Forward-only, idempotent, no
-- backfill.
-- ============================================================================

CREATE TABLE IF NOT EXISTS disk_usage_samples (
    volume_key  TEXT        NOT NULL,
    sampled_at  TIMESTAMPTZ NOT NULL,
    used_bytes  BIGINT      NOT NULL,
    total_bytes BIGINT      NOT NULL,
    PRIMARY KEY (volume_key, sampled_at)
);

CREATE INDEX IF NOT EXISTS idx_disk_usage_samples_sampled_at
    ON disk_usage_samples (sampled_at);

ALTER TABLE system_health_events
    ADD COLUMN IF NOT EXISTS last_reminded_at TIMESTAMPTZ;
