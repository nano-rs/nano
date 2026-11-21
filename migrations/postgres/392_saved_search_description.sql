-- NAN-5696: saved searches keep the description typed in the Save query dialog.
--
-- The dialog has always offered "Description (optional)", but the column did
-- not exist, so the text was dropped. Nullable, no default, no backfill:
-- existing saved searches simply have no description. Forward-only and
-- idempotent.

ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS description TEXT;
