-- NAN-1072: case saved searches.
--
-- Saved query strings for the /cases/search page. Each row is a named
-- query owned by a user; if `is_shared` is true the search is visible
-- to other users in the tenant (still owned + edit-rights gated by
-- owner_id).
--
-- The query column is the raw `field:value` text from the search bar
-- — same format the parser already understands. We don't store a
-- structured AST so we can iterate the parser without migrating data.

CREATE TABLE IF NOT EXISTS case_saved_searches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    query       TEXT NOT NULL,
    is_shared   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner_id, name)
);

CREATE INDEX IF NOT EXISTS idx_case_saved_searches_owner
    ON case_saved_searches (owner_id);

CREATE INDEX IF NOT EXISTS idx_case_saved_searches_shared
    ON case_saved_searches (is_shared) WHERE is_shared = TRUE;
