-- Durable state for the pinned MITRE ATT&CK catalog synchronizer.
-- A singleton row records failures/backoff separately from the append-only
-- successful-sync history in mitre_sync_metadata.

CREATE TABLE IF NOT EXISTS mitre_sync_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    status VARCHAR(16) NOT NULL DEFAULT 'idle'
        CHECK (status IN ('idle', 'syncing', 'succeeded', 'failed')),
    release_version VARCHAR(50),
    source_url TEXT,
    source_sha256 CHAR(64),
    tactic_count INTEGER,
    technique_count INTEGER,
    last_started_at TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    next_retry_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO mitre_sync_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

COMMENT ON TABLE mitre_sync_state IS
    'Singleton status/backoff record for the pinned MITRE ATT&CK catalog synchronizer';
