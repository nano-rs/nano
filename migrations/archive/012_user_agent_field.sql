-- Add user_agent field to logs table
-- Useful for web/HTTP log analysis

ALTER TABLE logs ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Index for user_agent queries
CREATE INDEX IF NOT EXISTS idx_logs_user_agent ON logs (user_agent);
