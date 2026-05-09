-- Add column to store OIDC groups from last login
-- This helps admins see what groups came in the token for mapping configuration

ALTER TABLE users ADD COLUMN IF NOT EXISTS last_oidc_groups TEXT[];

COMMENT ON COLUMN users.last_oidc_groups IS 'Groups from the most recent OIDC login token, for debugging group mappings';
