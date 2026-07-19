-- NAN-1918: MITRE catalog syncs must migrate rule mappings, not destroy them.
--
-- When MITRE renumbers a technique the sync deleted the old row (revoked STIX
-- objects are filtered out of the parse, then `DELETE FROM mitre_techniques
-- WHERE NOT (id = ANY(...))` reaps whatever is left over). Migration 230's
-- reconcile then quarantined every rule pointing at the old ID and blanked its
-- arrays. Nothing read the quarantine table, so the mappings were gone with no
-- operator-visible trace, and coverage *rose* because both the technique and
-- the rules covering it left the calculation.
--
-- The information needed to migrate those mappings is already in the STIX
-- bundle: revoked techniques carry `revoked-by` relationships naming their
-- successor (157 of them in v19.1, covering the full renumbering history).
-- The sync now harvests those into `mitre_technique_aliases`; this migration
-- adds the table plus the remap/repair machinery that consumes it.

CREATE TABLE IF NOT EXISTS public.mitre_technique_aliases (
    old_id VARCHAR(20) PRIMARY KEY,
    new_id VARCHAR(20) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mitre_technique_aliases_not_self CHECK (old_id <> new_id)
);

CREATE INDEX IF NOT EXISTS idx_mitre_technique_aliases_new
    ON public.mitre_technique_aliases (new_id);

COMMENT ON TABLE public.mitre_technique_aliases IS
    'Revoked ATT&CK technique ID -> its replacement, harvested from STIX revoked-by relationships. Deliberately has no FK to mitre_techniques: alias chains may pass through IDs that are themselves revoked, so resolution is transitive (see resolve_mitre_technique_alias).';

-- Track repair outcomes so a restored mapping is not re-restored on every sync
-- and so operators can see what happened to a quarantined rule.
ALTER TABLE public.detection_rule_mitre_mapping_quarantine
    ADD COLUMN IF NOT EXISTS repaired_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS repaired_tactics TEXT[],
    ADD COLUMN IF NOT EXISTS repaired_techniques TEXT[];

CREATE INDEX IF NOT EXISTS idx_detection_rule_mitre_quarantine_unrepaired
    ON public.detection_rule_mitre_mapping_quarantine (quarantined_at DESC)
    WHERE repaired_at IS NULL;

-- ---------------------------------------------------------------------------
-- Alias resolution
-- ---------------------------------------------------------------------------

-- Follow an alias chain to a technique that exists in the current catalog.
-- Returns NULL when the ID is unknown and has no alias path to a live
-- technique, which callers treat as "leave it alone and let validation fail".
CREATE OR REPLACE FUNCTION public.resolve_mitre_technique_alias(p_id TEXT)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    current_id TEXT := p_id;
    next_id    TEXT;
    hops       INTEGER := 0;
BEGIN
    IF p_id IS NULL THEN
        RETURN NULL;
    END IF;

    LOOP
        -- A live technique is its own answer. Revoked IDs are deleted from
        -- mitre_techniques by the sync, so anything still present is current.
        IF EXISTS (SELECT 1 FROM public.mitre_techniques WHERE id = current_id) THEN
            RETURN current_id;
        END IF;

        SELECT alias.new_id INTO next_id
        FROM public.mitre_technique_aliases AS alias
        WHERE alias.old_id = current_id;

        IF next_id IS NULL THEN
            RETURN NULL;
        END IF;

        current_id := next_id;
        hops := hops + 1;
        -- Defensive: a cycle in upstream data must not spin forever.
        IF hops > 16 THEN
            RETURN NULL;
        END IF;
    END LOOP;
END;
$$;

-- Migrate a (tactics, techniques) pair onto the current catalog.
--
-- Techniques resolve through the alias chain; anything unresolvable is left
-- verbatim so the caller's validation still rejects it loudly rather than
-- silently dropping a mapping.
--
-- Tactics are then recomputed, because a renumbered technique usually moves
-- tactic too (v19 moved T1562.001/TA0005 to T1685/TA0112):
--   1. keep listed tactics still supported by at least one resolved technique
--   2. for any resolved technique left orphaned by that set, add its tactics
-- Step 2 is what stops a remap from tripping the "technique does not belong to
-- a listed tactic" check on the very mapping we just migrated.
CREATE OR REPLACE FUNCTION public.remap_mitre_mapping(
    p_tactics TEXT[],
    p_techniques TEXT[],
    OUT out_tactics TEXT[],
    OUT out_techniques TEXT[]
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    SELECT ARRAY(
        SELECT DISTINCT COALESCE(public.resolve_mitre_technique_alias(item.value), item.value)
        FROM unnest(COALESCE(p_techniques, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY 1
    )
    INTO out_techniques;

    SELECT ARRAY(
        SELECT DISTINCT item.value
        FROM unnest(COALESCE(p_tactics, ARRAY[]::TEXT[])) AS item(value)
        WHERE EXISTS (
            SELECT 1
            FROM public.mitre_technique_tactics AS relationship
            WHERE relationship.tactic_id = item.value
              AND relationship.technique_id = ANY(out_techniques)
        )
        ORDER BY 1
    )
    INTO out_tactics;

    SELECT ARRAY(
        SELECT DISTINCT combined.tactic_id
        FROM (
            SELECT unnest(out_tactics) AS tactic_id
            UNION
            SELECT relationship.tactic_id
            FROM unnest(out_techniques) AS item(technique_id)
            JOIN public.mitre_technique_tactics AS relationship
              ON relationship.technique_id = item.technique_id
            WHERE NOT EXISTS (
                SELECT 1
                FROM public.mitre_technique_tactics AS kept
                WHERE kept.technique_id = item.technique_id
                  AND kept.tactic_id = ANY(out_tactics)
            )
        ) AS combined
        ORDER BY 1
    )
    INTO out_tactics;
END;
$$;

-- Does this mapping satisfy the same contract the enforcement trigger applies?
-- Kept as one function so the trigger, the reconcile pass and the repair pass
-- cannot drift apart on what "valid" means.
CREATE OR REPLACE FUNCTION public.mitre_mapping_rejection_reason(
    p_tactics TEXT[],
    p_techniques TEXT[]
)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN CARDINALITY(COALESCE(p_tactics, ARRAY[]::TEXT[])) = 0
             OR CARDINALITY(COALESCE(p_techniques, ARRAY[]::TEXT[])) = 0
            THEN 'incomplete tactic/technique mapping'
        WHEN EXISTS (
            SELECT 1 FROM unnest(p_tactics) AS requested(id)
            LEFT JOIN public.mitre_tactics AS tactic ON tactic.id = requested.id
            WHERE requested.id IS NULL
               OR requested.id !~ '^TA[0-9]{4}$'
               OR tactic.id IS NULL
        ) THEN 'unknown or malformed tactic ID'
        WHEN EXISTS (
            SELECT 1 FROM unnest(p_techniques) AS requested(id)
            LEFT JOIN public.mitre_techniques AS technique ON technique.id = requested.id
            WHERE requested.id IS NULL
               OR requested.id !~ '^T[0-9]{4}(\.[0-9]{3})?$'
               OR technique.id IS NULL
               OR COALESCE(technique.deprecated, FALSE)
        ) THEN 'unknown, malformed, or deprecated technique ID'
        WHEN EXISTS (
            SELECT 1 FROM unnest(p_techniques) AS requested(id)
            WHERE NOT EXISTS (
                SELECT 1 FROM public.mitre_technique_tactics AS relationship
                WHERE relationship.technique_id = requested.id
                  AND relationship.tactic_id = ANY(p_tactics)
            )
        ) THEN 'technique does not belong to a listed tactic'
        WHEN EXISTS (
            SELECT 1 FROM unnest(p_tactics) AS requested(id)
            WHERE NOT EXISTS (
                SELECT 1 FROM public.mitre_technique_tactics AS relationship
                WHERE relationship.tactic_id = requested.id
                  AND relationship.technique_id = ANY(p_techniques)
            )
        ) THEN 'tactic is not represented by a listed technique'
        ELSE NULL
    END;
$$;

-- ---------------------------------------------------------------------------
-- Write path: accept mappings authored against an older ATT&CK release
-- ---------------------------------------------------------------------------

-- Replaces the migration 230 trigger function. Only new behaviour: if a write
-- carries a technique ID that is revoked-but-aliased, migrate the mapping onto
-- the current catalog before validating. A rule authored against ATT&CK v18
-- therefore still imports.
--
-- This deliberately does NOT fire when every technique is already current: a
-- mapping that lists a tactic none of its techniques supports is an authoring
-- error, and must keep failing loudly rather than being silently "corrected".
CREATE OR REPLACE FUNCTION public.validate_detection_rule_mitre_mappings()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    invalid_id TEXT;
    remapped   RECORD;
    reason     TEXT;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.mitre_tactics IS NOT DISTINCT FROM OLD.mitre_tactics
       AND NEW.mitre_techniques IS NOT DISTINCT FROM OLD.mitre_techniques THEN
        RETURN NEW;
    END IF;

    NEW.mitre_tactics := ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(NEW.mitre_tactics, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
    );
    NEW.mitre_techniques := ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(NEW.mitre_techniques, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
    );

    -- Shape validation runs FIRST — before the empty checks and, critically,
    -- before the air-gapped early return below. An install with no catalog
    -- still knows 'BANANA' is not a tactic ID. Migration 230 ordered it this
    -- way deliberately; folding these into the catalog-aware checks silently
    -- disabled them on air-gapped deployments.
    SELECT COALESCE(value, '<null>') INTO invalid_id
    FROM unnest(NEW.mitre_tactics) AS item(value)
    WHERE value IS NULL OR value !~ '^TA[0-9]{4}$'
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT(
                'Invalid MITRE tactic ID %L; expected TA followed by four digits',
                invalid_id
            );
    END IF;

    SELECT COALESCE(value, '<null>') INTO invalid_id
    FROM unnest(NEW.mitre_techniques) AS item(value)
    WHERE value IS NULL OR value !~ '^T[0-9]{4}(\.[0-9]{3})?$'
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT(
                'Invalid MITRE technique ID %L; expected T followed by four digits and an optional three-digit sub-technique',
                invalid_id
            );
    END IF;

    IF CARDINALITY(NEW.mitre_tactics) = 0 AND CARDINALITY(NEW.mitre_techniques) = 0 THEN
        RETURN NEW;
    END IF;

    IF CARDINALITY(NEW.mitre_tactics) = 0 OR CARDINALITY(NEW.mitre_techniques) = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = 'MITRE tactics and techniques must either both be empty or both be provided';
    END IF;

    -- Air-gapped installs with no catalog cannot classify anything; migration
    -- 230 degrades to shape-only checks and this preserves that.
    IF NOT EXISTS (SELECT 1 FROM public.mitre_tactics)
       OR NOT EXISTS (SELECT 1 FROM public.mitre_techniques) THEN
        RETURN NEW;
    END IF;

    -- Migrate IDs renumbered by a catalog release the author predates.
    IF EXISTS (
        SELECT 1
        FROM unnest(NEW.mitre_techniques) AS requested(id)
        WHERE NOT EXISTS (SELECT 1 FROM public.mitre_techniques AS t WHERE t.id = requested.id)
          AND public.resolve_mitre_technique_alias(requested.id) IS NOT NULL
    ) THEN
        SELECT * INTO remapped
        FROM public.remap_mitre_mapping(NEW.mitre_tactics, NEW.mitre_techniques);

        -- Record it. A RAISE NOTICE never reaches an API caller, so without
        -- this row the write path would silently rewrite a caller's mapping —
        -- the same unaudited-mutation problem this migration exists to fix.
        -- Pre-resolved (repaired_at set), so it reads as history rather than as
        -- an outstanding problem, and the quarantine endpoint surfaces it.
        INSERT INTO public.detection_rule_mitre_mapping_quarantine (
            rule_id, original_tactics, original_techniques, reason,
            repaired_at, repaired_tactics, repaired_techniques
        )
        VALUES (
            NEW.id, NEW.mitre_tactics, NEW.mitre_techniques,
            'migrated onto the current ATT&CK catalog on write',
            NOW(), remapped.out_tactics, remapped.out_techniques
        );

        NEW.mitre_tactics := remapped.out_tactics;
        NEW.mitre_techniques := remapped.out_techniques;
    END IF;

    SELECT public.mitre_mapping_rejection_reason(NEW.mitre_tactics, NEW.mitre_techniques)
    INTO reason;

    IF reason IS NULL THEN
        RETURN NEW;
    END IF;

    -- Re-derive the offending ID so the message stays as specific as it was
    -- before this migration.
    IF reason = 'unknown or malformed tactic ID' THEN
        SELECT requested.id INTO invalid_id
        FROM unnest(NEW.mitre_tactics) AS requested(id)
        LEFT JOIN public.mitre_tactics AS tactic ON tactic.id = requested.id
        WHERE requested.id !~ '^TA[0-9]{4}$' OR tactic.id IS NULL
        LIMIT 1;
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('Unknown MITRE tactic %L; synchronize the ATT&CK catalog before saving this mapping', invalid_id);
    ELSIF reason = 'unknown, malformed, or deprecated technique ID' THEN
        SELECT requested.id INTO invalid_id
        FROM unnest(NEW.mitre_techniques) AS requested(id)
        LEFT JOIN public.mitre_techniques AS technique ON technique.id = requested.id
        WHERE requested.id !~ '^T[0-9]{4}(\.[0-9]{3})?$'
           OR technique.id IS NULL
           OR COALESCE(technique.deprecated, FALSE)
        LIMIT 1;
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('Unknown or deprecated MITRE technique %L', invalid_id);
    ELSIF reason = 'technique does not belong to a listed tactic' THEN
        SELECT requested.id INTO invalid_id
        FROM unnest(NEW.mitre_techniques) AS requested(id)
        WHERE NOT EXISTS (
            SELECT 1 FROM public.mitre_technique_tactics AS relationship
            WHERE relationship.technique_id = requested.id
              AND relationship.tactic_id = ANY(NEW.mitre_tactics)
        )
        LIMIT 1;
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('MITRE technique %L does not belong to any listed tactic', invalid_id);
    ELSIF reason = 'tactic is not represented by a listed technique' THEN
        SELECT requested.id INTO invalid_id
        FROM unnest(NEW.mitre_tactics) AS requested(id)
        WHERE NOT EXISTS (
            SELECT 1 FROM public.mitre_technique_tactics AS relationship
            WHERE relationship.tactic_id = requested.id
              AND relationship.technique_id = ANY(NEW.mitre_techniques)
        )
        LIMIT 1;
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('MITRE tactic %L is not represented by any listed technique', invalid_id);
    ELSE
        -- Unreachable today: the branches above cover every value
        -- mitre_mapping_rejection_reason returns that can survive the earlier
        -- guards. Kept so a new reason added there fails loudly with its own
        -- text instead of being mislabelled as one of the cases above.
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('Invalid MITRE mapping: %s', reason);
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Sync path: remap first, quarantine only what cannot be migrated
-- ---------------------------------------------------------------------------

-- Return type changes from BIGINT to a composite, so the old signature has to
-- go. The only caller is MitreRepository::replace_catalog_on.
DROP FUNCTION IF EXISTS public.reconcile_detection_rule_mitre_mappings();

CREATE FUNCTION public.reconcile_detection_rule_mitre_mappings(
    OUT remapped BIGINT,
    OUT quarantined BIGINT,
    OUT quarantined_rule_ids UUID[]
)
LANGUAGE plpgsql
AS $$
BEGIN
    remapped := 0;
    quarantined := 0;
    quarantined_rule_ids := ARRAY[]::UUID[];

    IF NOT EXISTS (SELECT 1 FROM public.mitre_tactics)
       OR NOT EXISTS (SELECT 1 FROM public.mitre_techniques) THEN
        RETURN;
    END IF;

    -- Pass 1: migrate everything the catalog can still explain.
    --
    -- Only already-invalid mappings are touched (the rejection_reason guard), so
    -- a healthy rule is never rewritten. Two things get fixed here: a renumbered
    -- technique resolves through the alias map, and a tactic no listed technique
    -- supports is dropped by remap_mitre_mapping's recomputation. The latter is
    -- narrower than what the author wrote — but the alternative on this path is
    -- deleting the mapping outright, so narrowing strictly wins.
    --
    -- Every such change writes a pre-resolved quarantine row. Silently editing a
    -- mapping with no audit trail is the exact failure this migration exists to
    -- fix, so the "we fixed it" case is recorded just as loudly as the "we could
    -- not fix it" case; the API surfaces both.
    WITH candidate AS (
        SELECT
            rule.id,
            rule.mitre_tactics AS old_tactics,
            rule.mitre_techniques AS old_techniques,
            migrated.out_tactics AS new_tactics,
            migrated.out_techniques AS new_techniques
        FROM public.detection_rules AS rule
        CROSS JOIN LATERAL public.remap_mitre_mapping(
            rule.mitre_tactics, rule.mitre_techniques
        ) AS migrated
        WHERE CARDINALITY(rule.mitre_techniques) > 0
          AND public.mitre_mapping_rejection_reason(rule.mitre_tactics, rule.mitre_techniques) IS NOT NULL
          AND public.mitre_mapping_rejection_reason(migrated.out_tactics, migrated.out_techniques) IS NULL
    ),
    migrated_rows AS (
        UPDATE public.detection_rules AS rule
        SET mitre_tactics = candidate.new_tactics,
            mitre_techniques = candidate.new_techniques,
            updated_at = NOW()
        FROM candidate
        WHERE rule.id = candidate.id
        RETURNING
            candidate.id AS rule_id,
            candidate.old_tactics,
            candidate.old_techniques,
            candidate.new_tactics,
            candidate.new_techniques
    )
    INSERT INTO public.detection_rule_mitre_mapping_quarantine (
        rule_id, original_tactics, original_techniques, reason,
        repaired_at, repaired_tactics, repaired_techniques
    )
    SELECT
        rule_id, old_tactics, old_techniques,
        'migrated onto the current ATT&CK catalog',
        NOW(), new_tactics, new_techniques
    FROM migrated_rows;

    GET DIAGNOSTICS remapped = ROW_COUNT;

    -- Pass 2: anything still invalid genuinely cannot be resolved.
    WITH classified AS (
        SELECT
            rule.id,
            rule.mitre_tactics,
            rule.mitre_techniques,
            public.mitre_mapping_rejection_reason(
                rule.mitre_tactics, rule.mitre_techniques
            ) AS reason
        FROM public.detection_rules AS rule
        WHERE CARDINALITY(rule.mitre_tactics) > 0
           OR CARDINALITY(rule.mitre_techniques) > 0
    ),
    logged AS (
        INSERT INTO public.detection_rule_mitre_mapping_quarantine (
            rule_id, original_tactics, original_techniques, reason
        )
        SELECT id, mitre_tactics, mitre_techniques, reason
        FROM classified
        WHERE reason IS NOT NULL
        RETURNING rule_id, original_tactics, original_techniques
    ),
    cleared AS (
        UPDATE public.detection_rules AS rule
        SET mitre_tactics = ARRAY[]::TEXT[],
            mitre_techniques = ARRAY[]::TEXT[],
            updated_at = NOW()
        FROM logged
        WHERE rule.id = logged.rule_id
          AND rule.mitre_tactics = logged.original_tactics
          AND rule.mitre_techniques = logged.original_techniques
        RETURNING rule.id
    )
    SELECT COUNT(*), COALESCE(ARRAY_AGG(id ORDER BY id), ARRAY[]::UUID[])
    INTO quarantined, quarantined_rule_ids
    FROM cleared;
END;
$$;

-- Restore mappings that an earlier sync destroyed, now that the alias map can
-- explain them. Only touches rules whose mapping is still empty, so an
-- operator's deliberate re-mapping is never overwritten.
CREATE OR REPLACE FUNCTION public.repair_quarantined_mitre_mappings()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    repaired BIGINT := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.mitre_technique_aliases) THEN
        RETURN 0;
    END IF;

    WITH latest AS (
        SELECT DISTINCT ON (quarantine.rule_id)
            quarantine.id,
            quarantine.rule_id,
            quarantine.original_tactics,
            quarantine.original_techniques
        FROM public.detection_rule_mitre_mapping_quarantine AS quarantine
        JOIN public.detection_rules AS rule ON rule.id = quarantine.rule_id
        WHERE quarantine.repaired_at IS NULL
          AND CARDINALITY(rule.mitre_tactics) = 0
          AND CARDINALITY(rule.mitre_techniques) = 0
        ORDER BY quarantine.rule_id, quarantine.quarantined_at DESC
    ),
    resolvable AS (
        SELECT
            latest.id,
            latest.rule_id,
            migrated.out_tactics,
            migrated.out_techniques
        FROM latest
        CROSS JOIN LATERAL public.remap_mitre_mapping(
            latest.original_tactics, latest.original_techniques
        ) AS migrated
        WHERE public.mitre_mapping_rejection_reason(
            migrated.out_tactics, migrated.out_techniques
        ) IS NULL
    ),
    restored AS (
        UPDATE public.detection_rules AS rule
        SET mitre_tactics = resolvable.out_tactics,
            mitre_techniques = resolvable.out_techniques,
            updated_at = NOW()
        FROM resolvable
        WHERE rule.id = resolvable.rule_id
        RETURNING resolvable.id AS quarantine_id,
                  resolvable.out_tactics,
                  resolvable.out_techniques
    )
    UPDATE public.detection_rule_mitre_mapping_quarantine AS quarantine
    SET repaired_at = NOW(),
        repaired_tactics = restored.out_tactics,
        repaired_techniques = restored.out_techniques
    FROM restored
    WHERE quarantine.id = restored.quarantine_id;

    GET DIAGNOSTICS repaired = ROW_COUNT;
    RETURN repaired;
END;
$$;

COMMENT ON FUNCTION public.repair_quarantined_mitre_mappings() IS
    'NAN-1918 self-heal: restores rule mappings destroyed by a pre-alias sync. Runs on every catalog sync; a no-op once the backlog is drained.';
