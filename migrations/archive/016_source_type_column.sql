-- Add source_type as a dedicated column for efficient filtering
-- Previously stored in metadata.source_type, now promoted to first-class column

-- Add the source_type column
ALTER TABLE logs ADD COLUMN IF NOT EXISTS source_type TEXT;

-- Create index for efficient filtering by source type
CREATE INDEX IF NOT EXISTS idx_logs_source_type ON logs (source_type, timestamp DESC);

-- Backfill existing data from metadata.source_type if present
UPDATE logs 
SET source_type = metadata->>'source_type'
WHERE source_type IS NULL 
  AND metadata->>'source_type' IS NOT NULL;
