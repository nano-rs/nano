-- Add progress column to melod_jobs for sub-agent status updates
ALTER TABLE melod_jobs ADD COLUMN IF NOT EXISTS progress TEXT;
