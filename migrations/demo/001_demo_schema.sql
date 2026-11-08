-- Demo mode schema
-- Only runs on DEPLOYMENT_MODE=demo deployments.
-- Regular deployments never create this schema.

CREATE SCHEMA IF NOT EXISTS demo;

-- Demo sessions: tracks each ephemeral demo user session
CREATE TABLE IF NOT EXISTS demo.sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(64) UNIQUE NOT NULL,
    burned_at TIMESTAMPTZ,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    display_name TEXT,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleaned_up BOOLEAN NOT NULL DEFAULT FALSE,
    cleaned_up_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_demo_sessions_token
    ON demo.sessions(token) WHERE burned_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_demo_sessions_expires
    ON demo.sessions(expires_at) WHERE cleaned_up = FALSE;

CREATE INDEX IF NOT EXISTS idx_demo_sessions_user
    ON demo.sessions(user_id);

-- Resource tracking: maps demo session → resources created by that session
-- Used for cleanup when session expires
CREATE TABLE IF NOT EXISTS demo.session_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES demo.sessions(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,  -- 'rule', 'case', 'dashboard', 'notebook', 'saved_search'
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_demo_resources_session
    ON demo.session_resources(session_id);

CREATE INDEX IF NOT EXISTS idx_demo_resources_type_id
    ON demo.session_resources(resource_type, resource_id);

-- Track applied demo migrations
CREATE TABLE IF NOT EXISTS demo.migrations (
    version INT PRIMARY KEY,
    filename TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
