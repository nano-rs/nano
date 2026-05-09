-- Add landing_page preference column to users table
-- Allows users to choose which page loads by default (search, home, cases, dashboards, rules)
ALTER TABLE users
ADD COLUMN IF NOT EXISTS landing_page VARCHAR(30) DEFAULT 'search';
