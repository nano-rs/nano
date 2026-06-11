-- NAN-1387: under the OCSF schema profile, folder-picker rule-repo syncs that
-- find no `-ocsf` sibling tree upstream now import the UDM rules flagged
-- conversion_status = 'untranslated' (instead of 'success'), so
-- schema-mismatched community rules surface honestly in the catalog rather
-- than importing as ready and silently never firing.

ALTER TABLE repository_rules DROP CONSTRAINT IF EXISTS repository_rules_conversion_status_check;
ALTER TABLE repository_rules ADD CONSTRAINT repository_rules_conversion_status_check
    CHECK (conversion_status IN ('pending', 'success', 'failed', 'manual', 'untranslated'));

COMMENT ON COLUMN repository_rules.conversion_status IS 'Conversion status: pending | success | failed | manual | untranslated (UDM rule imported under the OCSF profile with no -ocsf variant available)';
