-- Onboarding wizard progress tracking (per-user)
CREATE TABLE IF NOT EXISTS onboarding_progress (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    current_step VARCHAR(50) NOT NULL DEFAULT 'ai_setup',
    completed_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    skipped_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    step_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    dismissed BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
