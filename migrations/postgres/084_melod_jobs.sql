-- meloD async job storage (previously in-memory HashMap)
-- Shared across API replicas via PostgreSQL for multi-pod consistency.

CREATE TABLE IF NOT EXISTS melod_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    result JSONB,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_melod_jobs_created_by ON melod_jobs(created_by);

-- Partial index for cleanup: only targets completed/failed rows
CREATE INDEX IF NOT EXISTS idx_melod_jobs_cleanup ON melod_jobs(status, updated_at)
    WHERE status IN ('completed', 'failed');
