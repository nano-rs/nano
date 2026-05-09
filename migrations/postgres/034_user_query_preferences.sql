-- Add query mode preference to users table
-- Allows users to choose between Standard (PPL) and Advanced (Raw SQL) modes

ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_query_mode VARCHAR(20)
    DEFAULT 'standard'
    CHECK (preferred_query_mode IN ('standard', 'advanced'));

COMMENT ON COLUMN users.preferred_query_mode IS 'Query mode preference: standard (PPL) or advanced (Raw SQL)';
