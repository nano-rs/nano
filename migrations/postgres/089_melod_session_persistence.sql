-- meloD session persistence: persistent chat memory for AI agents
-- Stores conversation history for parser edit, query, detection, notebook, and chat agents

CREATE TABLE IF NOT EXISTS melod_sessions (
    session_id    TEXT PRIMARY KEY,
    user_id       UUID NOT NULL,
    agent_type    TEXT NOT NULL,
    context_key   TEXT NOT NULL,
    messages      JSONB NOT NULL DEFAULT '[]',
    artifacts     JSONB NOT NULL DEFAULT '[]',
    context_summary TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ttl_days      INTEGER NOT NULL DEFAULT 30
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_melod_sessions_slot
    ON melod_sessions(user_id, agent_type, context_key);

CREATE INDEX IF NOT EXISTS idx_melod_sessions_expiry
    ON melod_sessions(last_activity);

-- Tuning feedback loop: persist reviewer notes on proposal approval/rejection
ALTER TABLE tuning_proposals ADD COLUMN IF NOT EXISTS reviewer_notes TEXT;
