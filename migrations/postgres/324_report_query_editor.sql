-- NAN-5039: a report query edited by someone other than its owner runs under
-- the UNION of both principals' source deny sets.
--
-- A `settings:system` holder without `source_scopes:view_all` could PATCH
-- another user's report query and have it executed under the owner's wider
-- scope. Recording the last non-owner editor lets the runner narrow the
-- execution scope to what BOTH may see. NULL (every existing row, and any
-- query last saved by its owner) keeps today's owner-only scope.
--
-- Forward-only, no backfill. ON DELETE SET NULL: a deleted editor can no
-- longer read anything, so the owner's scope alone is correct again.

ALTER TABLE report_definitions
    ADD COLUMN IF NOT EXISTS query_edited_by UUID REFERENCES users(id) ON DELETE SET NULL;

COMMENT ON COLUMN report_definitions.query_edited_by IS
    'NAN-5039: last non-owner to change source_query; runs execute under owner deny set UNION this user''s deny set. NULL = owner-only.';
