-- NAN-5785: an immutable "first went live" time for a log source.
--
-- The feed monitor gives a source that has never sent an event one threshold
-- window of grace after it went live. `deployed_at` cannot anchor that: every
-- deploy, deploy-all and `mark_enabled_deployed` rewrites it, so a source that
-- never worked could have its grace window slid forward forever. The
-- application stamps this column once, the first time any path marks the
-- source deployed (`COALESCE(first_deployed_at, ...)`), and never rewrites it.
--
-- Forward-only, no backfill: for rows that predate it the stamp falls back to
-- `created_at` when the source was already deployed (an EARLIER anchor, so a
-- legacy source that never sent alerts sooner, never later), and the reader
-- falls back to the first successful deployment row, then `created_at`.

SET LOCAL lock_timeout = '5s';

ALTER TABLE public.log_sources ADD COLUMN IF NOT EXISTS first_deployed_at TIMESTAMPTZ;
