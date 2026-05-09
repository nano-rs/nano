-- Track lookup table ownership: who created the table (NAN-514)
--
-- Adds an optional creator FK to the lookup tables registry so the
-- redesigned LookupTableView inspector + LookupTables list owner column
-- can surface the user who created each table.
--
-- Existing rows have NULL `created_by_user_id` and continue to render as
-- `—` in the UI (no backfill — historical creator is not recoverable).
-- ON DELETE SET NULL preserves the lookup table when its creator is
-- deleted from the system.

ALTER TABLE lookup_tables_registry
ADD COLUMN IF NOT EXISTS created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_lookup_tables_created_by
ON lookup_tables_registry(created_by_user_id)
WHERE created_by_user_id IS NOT NULL;
