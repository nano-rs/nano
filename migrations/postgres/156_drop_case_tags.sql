-- NAN-433: drop the unused `tags` column from the cases table.
--
-- Tags were never wired to the redesign UI (dead Add-tag button removed in
-- NAN-432) and the structured dimensions we already capture — disposition,
-- close_reason enum, MITRE techniques, queues, case relations, severity and
-- status — cover the workflows a free-form tag field would serve. No
-- production data depends on the column; the original schema defaulted it
-- to '{}'.
--
-- If tags come back, redesign the vocabulary as a constrained enum or a
-- tag-catalog table rather than reviving this free-form text[] column.

ALTER TABLE cases DROP COLUMN IF EXISTS tags;
