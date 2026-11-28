-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5976: the time spans in which `scripts/nano upgrade` was restarting
-- services, as the upgrade recorded them.
--
-- The upgrade's SIEM Health gate (NAN-5528 / NAN-5958) already treats a
-- ClickHouse error counter (MEMORY_LIMIT_EXCEEDED, CACHE_DICTIONARY_UPDATE_FAIL)
-- whose last occurrence falls inside its own rollout window, and that was not
-- happening before the upgrade, as an upgrade transient. SIEM Health reads
-- `system.errors` over 24 hours, so without this table it kept counting that
-- one error and reported CRITICAL for a day after a clean upgrade.
--
-- The upgrade writes one row per window (the run's first step to the start of
-- its SIEM Health check, plus each nano-jobs restart it made for a fresh
-- report) and the ClickHouse error baseline it captured before the upgrade.
-- `starts_at` / `ends_at` are on ClickHouse's clock (the upgrade converts its
-- own times with ClickHouse's now()), so SIEM Health compares them with
-- `system.errors.last_error_time` directly. Once a SIEM Health report has
-- scored a ClickHouse error while a run's windows were recorded, SIEM Health
-- sets `error_scored_at`; from then on the upgrade never adds to, replaces or
-- extends that run's windows. Additive, forward-only, idempotent.
CREATE TABLE IF NOT EXISTS upgrade_rollout_windows (
    run_id TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    -- `system.errors` before the upgrade: {"captured_at": "...Z", "errors":
    -- {"<NAME>": {"value": n, "last_at": "...Z"}}}. NULL when the upgrade could
    -- not read it; such a window never excuses an error.
    clickhouse_errors_before JSONB,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set by SIEM Health the first time a report scores an error counter
    -- while this run's windows exist. The run's windows are then frozen.
    error_scored_at TIMESTAMPTZ,
    PRIMARY KEY (run_id, starts_at),
    CONSTRAINT upgrade_rollout_windows_bounded CHECK (ends_at >= starts_at)
);

CREATE INDEX IF NOT EXISTS idx_upgrade_rollout_windows_ends_at
    ON upgrade_rollout_windows (ends_at);

COMMENT ON TABLE upgrade_rollout_windows IS
    'Rollout windows recorded by scripts/nano upgrade; SIEM Health does not count ClickHouse errors from inside them (NAN-5976)';
