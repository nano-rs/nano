-- Add search_hub_style user preference column
-- Allows users to choose between popover and drawer styles for the Search Hub

ALTER TABLE users
ADD COLUMN IF NOT EXISTS search_hub_style VARCHAR(20) DEFAULT 'popover';
