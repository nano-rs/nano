-- F-33: one-time backfill of alerts.source_types (migration 246) and
-- detection_matches.source_types (migration 247) for pre-feature rows.
--
-- PROBLEM: migrations 246/247 added `source_types TEXT[] NOT NULL DEFAULT '{}'`
-- with NO backfill. Empty `'{}'` is read as "visible to everyone" by the
-- per-source RBAC read filter (`$N::text[] = '{}' OR NOT (col && $N::text[])`).
-- So every DETECTION alert / detection_match created before the feature carries
-- `'{}'` and leaks to source-denied viewers even when its
-- `matched_events[0].source_type` is a restricted source.
--
-- OVERLOADED-EMPTY CONSTRAINT: `'{}'` legitimately also means "source-less
-- producer" for the observability/risk alert kinds (metric_monitor / slo /
-- synthetic / risk_notable), which MUST stay visible. So we ONLY touch
-- `alerts.kind = 'detection'`; other kinds keep `'{}'`. `detection_matches` has
-- no `kind` column — every row there is detection-derived, so all empty-stamp
-- rows are eligible.
--
-- DERIVATION (mirrors `AlertRepository::distinct_source_types`,
-- nanosiem-core/src/db/repository/alerts.rs): for each element of the
-- `matched_events` jsonb array, take the per-event `source_type` string AND
-- every element of the per-event `_nano_source_types` array (the aggregate
-- stamp), trimmed + lowercased, distinct, dropping blanks. `matched_events` is
-- jsonb (001_init_postgres.sql) — guarded with a `jsonb_typeof(...) = 'array'`
-- CASE so a malformed non-array payload feeds an empty array instead of raising.
--
-- FAIL-CLOSED: where derivation yields nothing (aggregate rows that carried no
-- stamp, malformed payloads), stamp the CURRENT FULL restricted registry
-- (migration 244 `restricted_source_types`). If the registry is empty (the
-- default deployment — nothing is restricted) that resolves to `'{}'` = visible,
-- which is correct. We only UPDATE when the final stamp is non-empty, so the
-- empty-registry case is a no-op and the migration stays idempotent
-- (`WHERE source_types = '{}'`).

-- ---------------------------------------------------------------------------
-- alerts: detection kind only
-- ---------------------------------------------------------------------------
WITH reg AS (
    -- F-33: the fail-closed fallback = the full restricted registry, normalized
    -- (trim + lower) to match the deny-set the read filter binds. Blank rows are
    -- filtered so a degenerate registry entry can't stamp an empty value.
    SELECT COALESCE(
        array_agg(DISTINCT lower(trim(source_type)))
            FILTER (WHERE trim(COALESCE(source_type, '')) <> ''),
        '{}'
    )::text[] AS restricted
    FROM restricted_source_types
),
derived AS (
    SELECT
        a.id,
        COALESCE(
            (
                SELECT array_agg(DISTINCT st ORDER BY st)
                FROM (
                    -- per-event `source_type` (raw / grouped-raw detection rules)
                    SELECT lower(trim(elem->>'source_type')) AS st
                    FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(a.matched_events) = 'array'
                             THEN a.matched_events ELSE '[]'::jsonb END
                    ) AS elem
                    WHERE jsonb_typeof(elem->'source_type') = 'string'
                      AND trim(elem->>'source_type') <> ''
                    UNION
                    -- per-event `_nano_source_types` array (aggregate-rule stamp)
                    SELECT lower(trim(nst.val)) AS st
                    FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(a.matched_events) = 'array'
                             THEN a.matched_events ELSE '[]'::jsonb END
                    ) AS elem
                    CROSS JOIN LATERAL jsonb_array_elements_text(
                        CASE WHEN jsonb_typeof(elem->'_nano_source_types') = 'array'
                             THEN elem->'_nano_source_types' ELSE '[]'::jsonb END
                    ) AS nst(val)
                    WHERE trim(COALESCE(nst.val, '')) <> ''
                ) s
            ),
            '{}'::text[]
        ) AS derived_types
    FROM alerts a
    WHERE a.kind = 'detection'
      AND a.source_types = '{}'
)
UPDATE alerts a
SET source_types = CASE
        WHEN d.derived_types <> '{}'::text[] THEN d.derived_types
        ELSE reg.restricted
    END
FROM derived d CROSS JOIN reg
WHERE a.id = d.id
  AND a.kind = 'detection'
  AND a.source_types = '{}'  -- F-33: idempotent guard
  AND (CASE WHEN d.derived_types <> '{}'::text[]
            THEN d.derived_types ELSE reg.restricted END) <> '{}'::text[];

-- ---------------------------------------------------------------------------
-- detection_matches: every row is detection-derived (no kind column)
-- ---------------------------------------------------------------------------
WITH reg AS (
    SELECT COALESCE(
        array_agg(DISTINCT lower(trim(source_type)))
            FILTER (WHERE trim(COALESCE(source_type, '')) <> ''),
        '{}'
    )::text[] AS restricted
    FROM restricted_source_types
),
derived AS (
    SELECT
        m.id,
        COALESCE(
            (
                SELECT array_agg(DISTINCT st ORDER BY st)
                FROM (
                    SELECT lower(trim(elem->>'source_type')) AS st
                    FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(m.matched_events) = 'array'
                             THEN m.matched_events ELSE '[]'::jsonb END
                    ) AS elem
                    WHERE jsonb_typeof(elem->'source_type') = 'string'
                      AND trim(elem->>'source_type') <> ''
                    UNION
                    SELECT lower(trim(nst.val)) AS st
                    FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(m.matched_events) = 'array'
                             THEN m.matched_events ELSE '[]'::jsonb END
                    ) AS elem
                    CROSS JOIN LATERAL jsonb_array_elements_text(
                        CASE WHEN jsonb_typeof(elem->'_nano_source_types') = 'array'
                             THEN elem->'_nano_source_types' ELSE '[]'::jsonb END
                    ) AS nst(val)
                    WHERE trim(COALESCE(nst.val, '')) <> ''
                ) s
            ),
            '{}'::text[]
        ) AS derived_types
    FROM detection_matches m
    WHERE m.source_types = '{}'
)
UPDATE detection_matches m
SET source_types = CASE
        WHEN d.derived_types <> '{}'::text[] THEN d.derived_types
        ELSE reg.restricted
    END
FROM derived d CROSS JOIN reg
WHERE m.id = d.id
  AND m.source_types = '{}'  -- F-33: idempotent guard
  AND (CASE WHEN d.derived_types <> '{}'::text[]
            THEN d.derived_types ELSE reg.restricted END) <> '{}'::text[];
