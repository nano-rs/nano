-- Migration: Replace enabled boolean with Paused rule mode
--
-- The enabled boolean is redundant with the mode enum. This migration:
-- 1. Converts disabled+alerting rules to paused mode
-- 2. Converts disabled+live/staging rules to staging mode
-- 3. Adds 'paused' to the mode CHECK constraint
-- 4. Drops the enabled column
-- 5. Removes the detections:enable permission (pause/resume uses detections:promote)

-- Step 1: Convert disabled rules based on their previous mode
UPDATE detection_rules SET mode = 'paused' WHERE enabled = false AND mode = 'alerting';
UPDATE detection_rules SET mode = 'staging' WHERE enabled = false AND mode IN ('staging', 'live');

-- Step 2: Update the CHECK constraint to allow 'paused'
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_mode_check;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_mode_check
  CHECK (mode = ANY (ARRAY['staging', 'live', 'alerting', 'paused']));

-- Step 3: Drop the enabled column
ALTER TABLE detection_rules DROP COLUMN IF EXISTS enabled;

-- Step 4: Remove the detections:enable permission
-- (pause/resume will use detections:promote instead)
DELETE FROM role_permissions WHERE permission_id = 'detections:enable';
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'api_key_permissions') THEN
    DELETE FROM api_key_permissions WHERE permission_id = 'detections:enable';
  END IF;
END $$;
DELETE FROM permissions WHERE id = 'detections:enable';
