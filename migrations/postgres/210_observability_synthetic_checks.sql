-- NAN-1538: Synthetic checks for the Observability console.
--
-- A synthetic check is an active probe (today: HTTP GET) executed on an
-- interval by the nanosiem-jobs synthetics runner. The check *definition* —
-- what to probe and how often — is tenant metadata and lives here in
-- PostgreSQL. The probe *results* (one row per execution) live in ClickHouse
-- (`nanosiem.synthetic_check_results`, migration 142), written by the runner.
--
-- The live summary fields surfaced in the console (uptime_pct, p50 latency,
-- last-N history) are NOT stored here — the API layer computes them on read
-- from the ClickHouse results and merges them onto each definition, mirroring
-- the SLO subsystem (migration 209).

CREATE TABLE IF NOT EXISTS observability_synthetic_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Human label for the check card (e.g. "Login page").
    name TEXT NOT NULL,
    -- Probe type. Only 'http' ships today; the column leaves room for
    -- 'tcp'/'browser' later. Validated at the API layer; CHECK guards the DB.
    check_type TEXT NOT NULL DEFAULT 'http' CHECK (check_type IN ('http')),
    -- The URL to probe.
    target_url TEXT NOT NULL,
    -- How often to run the check, in seconds (30..=3600).
    interval_secs INTEGER NOT NULL CHECK (interval_secs >= 30 AND interval_secs <= 3600),
    -- HTTP status that counts as a success.
    expected_status INTEGER NOT NULL DEFAULT 200,
    -- Per-run request timeout in seconds.
    timeout_secs INTEGER NOT NULL DEFAULT 10,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The runner selects enabled checks each tick; index keeps that scan cheap.
CREATE INDEX IF NOT EXISTS idx_observability_synthetic_checks_enabled
    ON observability_synthetic_checks (enabled);
