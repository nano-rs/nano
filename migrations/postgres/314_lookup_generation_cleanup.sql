-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4958: durable cleanup journal for staged and retired lookup generations.
--
-- A generation is recorded before staging begins. Publishing a replacement
-- changes the staged row to live (removes it from this journal) and records the
-- previous physical generation as retired in the same PostgreSQL transaction
-- as the registry pointer switch. Cleanup may then fail without losing the
-- work: the leader-only jobs reconciler retries every unreferenced generation.

CREATE TABLE IF NOT EXISTS lookup_generation_cleanup (
    physical_name TEXT PRIMARY KEY,
    logical_name TEXT NOT NULL,
    storage_backend TEXT NOT NULL
        CHECK (storage_backend IN ('postgres', 'clickhouse')),
    generation_state TEXT NOT NULL
        CHECK (generation_state IN ('staged', 'retired')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lookup_generation_cleanup_due
    ON lookup_generation_cleanup (next_attempt_at, created_at);
