-- NAN-5716: detect local edits ("DRIFT") on rules imported from a repository.
--
-- `rule_imports` recorded which commit a detection rule was imported or last
-- synced from, but nothing about the detection rule's own content at that
-- moment, so a later local edit was invisible: the Rule Repositories page kept
-- reading IMPORTED and a one-click upstream Update would silently overwrite it.
--
-- `synced_content_hash` is the hash of the upstream-managed columns of the
-- linked detection rule, stamped when the import is created and every time an
-- upstream update is applied (RuleImportsRepository::create / ::update_sync).
-- An import whose rule's current hash differs reads DRIFT. That holds for
-- linked AND forked imports: both are flagged on upstream changes and both are
-- overwritten by a one-click upstream Update (import_rule), so a local edit to
-- either is what that Update would silently discard. NULL means "no baseline"
-- and never reads DRIFT.
--
-- The hashed columns are exactly the ones an upstream update rewrites
-- (`import_rule`'s update branch): query, description, severity, MITRE
-- tactics/techniques, schedule, lookback and tags. Lifecycle state (mode,
-- enabled/paused, folder, name) is local by design and is not drift.
--
-- Both sides (stamp and read) go through the same canonical form, so a save
-- that changes only representation is not an edit: NULL and empty alike,
-- CRLF -> LF and surrounding whitespace trimmed on query / description /
-- schedule, severity lowercased, arrays deduplicated and sorted (tags also
-- trimmed, blanks dropped), all serialized as one jsonb array. lookback stays
-- as stored: NULL ("rule default") and a number are different rules.
--
-- The function is the single definition: Rust calls it on stamp and on read,
-- so the two can never disagree.

ALTER TABLE rule_imports ADD COLUMN IF NOT EXISTS synced_content_hash TEXT;

COMMENT ON COLUMN rule_imports.synced_content_hash IS
    'rule_import_content_hash() of the imported detection rule when imported or last synced from upstream; a different current hash = local drift (NAN-5716)';

CREATE OR REPLACE FUNCTION rule_import_content_hash(
    p_query TEXT,
    p_description TEXT,
    p_severity TEXT,
    p_mitre_tactics TEXT[],
    p_mitre_techniques TEXT[],
    p_schedule_cron TEXT,
    p_lookback_minutes INTEGER,
    p_tags TEXT[]
) RETURNS TEXT
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT md5(jsonb_build_array(
        btrim(replace(COALESCE(p_query, ''), E'\r\n', E'\n'), E' \t\r\n'),
        btrim(replace(COALESCE(p_description, ''), E'\r\n', E'\n'), E' \t\r\n'),
        lower(btrim(COALESCE(p_severity, ''))),
        ARRAY(SELECT DISTINCT t FROM unnest(COALESCE(p_mitre_tactics, '{}'::text[])) AS u(t) ORDER BY t),
        ARRAY(SELECT DISTINCT t FROM unnest(COALESCE(p_mitre_techniques, '{}'::text[])) AS u(t) ORDER BY t),
        btrim(COALESCE(p_schedule_cron, '')),
        p_lookback_minutes,
        ARRAY(
            SELECT DISTINCT btrim(t) FROM unnest(COALESCE(p_tags, '{}'::text[])) AS u(t)
            WHERE btrim(t) <> '' ORDER BY 1
        )
    )::text)
$$;

-- Baseline existing imports at their current content: edits made before this
-- migration cannot be told apart from the import, so they start clean and
-- every edit from here on is detected. rule_imports is a small metadata table
-- (one row per imported rule); this is a bounded single UPDATE.
UPDATE rule_imports ri
SET synced_content_hash = rule_import_content_hash(
    dr.query, dr.description, dr.severity, dr.mitre_tactics,
    dr.mitre_techniques, dr.schedule_cron, dr.lookback_minutes, dr.tags)
FROM detection_rules dr
WHERE dr.id = ri.detection_rule_id
  AND ri.synced_content_hash IS NULL;
