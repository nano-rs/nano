-- Canonical MITRE ATT&CK mappings are a detection-rule integrity contract.
-- Keep the arrays for API compatibility, but validate them against the catalog
-- at the database boundary so imports and future write paths cannot bypass it.

CREATE TABLE IF NOT EXISTS public.detection_rule_mitre_mapping_quarantine (
    id BIGSERIAL PRIMARY KEY,
    rule_id UUID NOT NULL,
    original_tactics TEXT[] NOT NULL,
    original_techniques TEXT[] NOT NULL,
    reason TEXT NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_rule_mitre_quarantine_rule
    ON public.detection_rule_mitre_mapping_quarantine (rule_id, quarantined_at DESC);

COMMENT ON TABLE public.detection_rule_mitre_mapping_quarantine IS
    'Audit record for legacy rule mappings removed from coverage after catalog validation failed';

-- Canonicalize legacy case/order/duplicates before the enforcement trigger is
-- installed. Unknown legacy values are preserved until a complete catalog is
-- available to classify and quarantine them below.
UPDATE public.detection_rules AS rule
SET mitre_tactics = ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(rule.mitre_tactics, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
    ),
    mitre_techniques = ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(rule.mitre_techniques, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
    )
WHERE rule.mitre_tactics IS NULL
   OR rule.mitre_techniques IS NULL
   OR rule.mitre_tactics IS DISTINCT FROM ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(rule.mitre_tactics, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
   )
   OR rule.mitre_techniques IS DISTINCT FROM ARRAY(
        SELECT DISTINCT UPPER(BTRIM(value))
        FROM unnest(COALESCE(rule.mitre_techniques, ARRAY[]::TEXT[])) AS item(value)
        ORDER BY UPPER(BTRIM(value))
   );

CREATE OR REPLACE FUNCTION public.validate_detection_rule_mitre_mappings()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    invalid_id TEXT;
BEGIN
    -- Repository updates mention both array columns through COALESCE even for
    -- unrelated edits. Do not turn a catalog outage into a blanket rule-edit
    -- outage when the mapping itself did not change.
    IF TG_OP = 'UPDATE'
       AND OLD.mitre_tactics IS NOT DISTINCT FROM NEW.mitre_tactics
       AND OLD.mitre_techniques IS NOT DISTINCT FROM NEW.mitre_techniques THEN
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

    IF CARDINALITY(NEW.mitre_tactics) = 0
       AND CARDINALITY(NEW.mitre_techniques) = 0 THEN
        RETURN NEW;
    END IF;
    IF CARDINALITY(NEW.mitre_tactics) = 0
       OR CARDINALITY(NEW.mitre_techniques) = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = 'MITRE tactics and techniques must either both be empty or both be provided';
    END IF;

    -- Air-gapped installs never seed the ATT&CK catalog (outbound sync is
    -- egress-gated off), so the catalog tables stay empty. Degrade to
    -- format-only validation while the catalog is empty: the shape checks above
    -- still run, but we cannot resolve catalog membership or technique/tactic
    -- relationships without a catalog, and refusing every mapping would 422
    -- every rule create/import on an air-gapped deployment. Mirrors the
    -- empty-catalog guard in reconcile_detection_rule_mitre_mappings below, which
    -- re-validates any mapping authored in this window once a catalog lands.
    IF NOT EXISTS (SELECT 1 FROM public.mitre_tactics)
       OR NOT EXISTS (SELECT 1 FROM public.mitre_techniques) THEN
        RETURN NEW;
    END IF;

    SELECT requested.id INTO invalid_id
    FROM unnest(NEW.mitre_tactics) AS requested(id)
    LEFT JOIN public.mitre_tactics AS tactic ON tactic.id = requested.id
    WHERE tactic.id IS NULL
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT(
                'Unknown MITRE tactic %L; synchronize the ATT&CK catalog before saving this mapping',
                invalid_id
            );
    END IF;

    SELECT requested.id INTO invalid_id
    FROM unnest(NEW.mitre_techniques) AS requested(id)
    LEFT JOIN public.mitre_techniques AS technique ON technique.id = requested.id
    WHERE technique.id IS NULL OR COALESCE(technique.deprecated, FALSE)
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT('Unknown or deprecated MITRE technique %L', invalid_id);
    END IF;

    -- Every technique must belong to at least one listed tactic. This covers
    -- parent and sub-technique IDs using the catalog's explicit relationship.
    SELECT technique_id INTO invalid_id
    FROM unnest(NEW.mitre_techniques) AS requested(technique_id)
    WHERE NOT EXISTS (
        SELECT 1
        FROM public.mitre_technique_tactics AS relationship
        WHERE relationship.technique_id = requested.technique_id
          AND relationship.tactic_id = ANY(NEW.mitre_tactics)
    )
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT(
                'MITRE technique %L does not belong to any listed tactic',
                invalid_id
            );
    END IF;

    -- Conversely, do not retain a tactic label that none of the mapped
    -- techniques supports; that would inflate tactic-level coverage.
    SELECT tactic_id INTO invalid_id
    FROM unnest(NEW.mitre_tactics) AS requested(tactic_id)
    WHERE NOT EXISTS (
        SELECT 1
        FROM public.mitre_technique_tactics AS relationship
        WHERE relationship.tactic_id = requested.tactic_id
          AND relationship.technique_id = ANY(NEW.mitre_techniques)
    )
    LIMIT 1;
    IF invalid_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'detection_rules_mitre_mapping_check',
            MESSAGE = FORMAT(
                'MITRE tactic %L is not represented by any listed technique',
                invalid_id
            );
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS validate_detection_rule_mitre_mappings
    ON public.detection_rules;
CREATE TRIGGER validate_detection_rule_mitre_mappings
BEFORE INSERT OR UPDATE OF mitre_tactics, mitre_techniques
ON public.detection_rules
FOR EACH ROW
EXECUTE FUNCTION public.validate_detection_rule_mitre_mappings();

-- Reconcile mappings created before enforcement only after both sides of a
-- catalog exist. Invalid arrays are retained in an append-only quarantine row,
-- then cleared so coverage cannot count a mapping the catalog cannot resolve.
CREATE OR REPLACE FUNCTION public.reconcile_detection_rule_mitre_mappings()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    quarantined BIGINT := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.mitre_tactics)
       OR NOT EXISTS (SELECT 1 FROM public.mitre_techniques) THEN
        RETURN 0;
    END IF;

    WITH classified AS (
        SELECT
            rule.id,
            rule.mitre_tactics,
            rule.mitre_techniques,
            CASE
                WHEN CARDINALITY(rule.mitre_tactics) = 0
                     OR CARDINALITY(rule.mitre_techniques) = 0
                    THEN 'incomplete tactic/technique mapping'
                WHEN EXISTS (
                    SELECT 1 FROM unnest(rule.mitre_tactics) AS requested(id)
                    LEFT JOIN public.mitre_tactics AS tactic ON tactic.id = requested.id
                    WHERE requested.id IS NULL
                       OR requested.id !~ '^TA[0-9]{4}$'
                       OR tactic.id IS NULL
                ) THEN 'unknown or malformed tactic ID'
                WHEN EXISTS (
                    SELECT 1 FROM unnest(rule.mitre_techniques) AS requested(id)
                    LEFT JOIN public.mitre_techniques AS technique ON technique.id = requested.id
                    WHERE requested.id IS NULL
                       OR requested.id !~ '^T[0-9]{4}(\.[0-9]{3})?$'
                       OR technique.id IS NULL
                       OR COALESCE(technique.deprecated, FALSE)
                ) THEN 'unknown, malformed, or deprecated technique ID'
                WHEN EXISTS (
                    SELECT 1 FROM unnest(rule.mitre_techniques) AS requested(id)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM public.mitre_technique_tactics AS relationship
                        WHERE relationship.technique_id = requested.id
                          AND relationship.tactic_id = ANY(rule.mitre_tactics)
                    )
                ) THEN 'technique does not belong to a listed tactic'
                WHEN EXISTS (
                    SELECT 1 FROM unnest(rule.mitre_tactics) AS requested(id)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM public.mitre_technique_tactics AS relationship
                        WHERE relationship.tactic_id = requested.id
                          AND relationship.technique_id = ANY(rule.mitre_techniques)
                    )
                ) THEN 'tactic is not represented by a listed technique'
                ELSE NULL
            END AS reason
        FROM public.detection_rules AS rule
        WHERE CARDINALITY(rule.mitre_tactics) > 0
           OR CARDINALITY(rule.mitre_techniques) > 0
    ),
    logged AS (
        INSERT INTO public.detection_rule_mitre_mapping_quarantine (
            rule_id,
            original_tactics,
            original_techniques,
            reason
        )
        SELECT id, mitre_tactics, mitre_techniques, reason
        FROM classified
        WHERE reason IS NOT NULL
        RETURNING rule_id, original_tactics, original_techniques
    )
    UPDATE public.detection_rules AS rule
    SET mitre_tactics = ARRAY[]::TEXT[],
        mitre_techniques = ARRAY[]::TEXT[],
        updated_at = NOW()
    FROM logged
    WHERE rule.id = logged.rule_id
      AND rule.mitre_tactics = logged.original_tactics
      AND rule.mitre_techniques = logged.original_techniques;

    GET DIAGNOSTICS quarantined = ROW_COUNT;
    RETURN quarantined;
END;
$$;

SELECT public.reconcile_detection_rule_mitre_mappings();
