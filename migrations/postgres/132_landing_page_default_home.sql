-- Change default landing page from 'search' to 'home'
-- Update existing users who still have the old default
ALTER TABLE users ALTER COLUMN landing_page SET DEFAULT 'home';
UPDATE users SET landing_page = 'home' WHERE landing_page = 'search';
