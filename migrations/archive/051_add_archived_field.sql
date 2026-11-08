-- Add archived field to detection_rules table
-- Archived rules are hidden by default and cannot be enabled until unarchived

ALTER TABLE detection_rules 
ADD COLUMN archived BOOLEAN NOT NULL DEFAULT FALSE;

-- Create index for filtering archived rules
CREATE INDEX idx_detection_rules_archived ON detection_rules(archived);

-- Ensure archived rules are disabled
UPDATE detection_rules SET enabled = FALSE WHERE archived = TRUE;
