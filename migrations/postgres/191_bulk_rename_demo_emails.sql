-- NAN-936 F-12: bulk-rename existing demo users to the canonical
-- `@demo.nano.local` domain. Migration 187 covered the system-ai
-- row; the AuthContext + nanosiem-core demo service mint NEW demo
-- emails with the canonical domain already (NAN-910). Rows seeded
-- before NAN-910 still carry `@demo.nanosiem.local`, and on the
-- Saturn demo tenant those aren't ephemeral session rows — they're
-- real users, so the legacy domain visibly leaks into
-- /settings/access-control.
--
-- `users.email` has a UNIQUE constraint, but every source row's
-- username portion is `demo-<uuid>` which is structurally unique,
-- so a domain-only swap can't collide with another renamed row. The
-- only collision path is if an operator pre-created a target row
-- by hand on a non-demo tenant — vanishingly unlikely.

UPDATE users
SET email = regexp_replace(email, '@demo\.nanosiem\.local$', '@demo.nano.local')
WHERE email LIKE '%@demo.nanosiem.local';
