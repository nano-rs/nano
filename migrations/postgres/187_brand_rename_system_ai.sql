-- NAN-910 F-12: move the system AI user to the canonical `nano.local` domain.
-- Migrations 078 + 177 seeded this row's email as `system-ai@nanosiem.local`
-- via INSERT ... ON CONFLICT (id) DO NOTHING, so on upgrade the email never
-- gets refreshed without an explicit UPDATE. Migration 119 already renamed
-- the display name to "pivt", so we only touch the email here.

UPDATE users
SET email = 'system-ai@nano.local'
WHERE id = '00000000-0000-0000-0000-000000000099'
  AND email = 'system-ai@nanosiem.local';
