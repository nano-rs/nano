-- NAN-5869: re-derive `requires_fields` of already-synced repository rules.
--
-- The required-field extractor read a UDM name from the last segment of an
-- OCSF path (`traffic.bytes_out` -> `bytes_out`, `email.subject` ->
-- `subject`) and from the first segment in `by` lists (`by user.name` ->
-- `user`), so official OCSF rules reported UDM fields they never use.
-- `requires_fields` is stored at sync time, and sync skips a repository
-- whose upstream commit is unchanged, so an upgraded install would keep the
-- wrong lists until the upstream repository moved.
--
-- Forgetting the last synced commit makes the next sync walk the rule files
-- once. A file whose SHA is unchanged only gets its `requires_fields`
-- re-derived (and copied to the detection rules imported from it): no
-- content rewrite, no "upstream changed" mark. Postgres metadata only; no
-- event data is touched. Forward-only; running it again is harmless (one
-- extra file walk).
UPDATE rule_repositories
SET last_sync_commit = NULL
WHERE last_sync_commit IS NOT NULL;
