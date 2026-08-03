-- NAN-2305: unique the GENERATED Vector identity, not just the display name.
--
-- `log_sources.name` and `source_configurations.name` are both UNIQUE, but
-- only as raw strings — and nothing the deploy writes uses the raw string.
-- Every generated artifact is keyed on `vector_naming::safe_name`, which
-- lowercases the name and collapses every non-alphanumeric to `_`:
--
--   * `sources/parsers/<safe>.toml` / `sources/configs/<safe>.toml` filenames
--   * `[transforms.<safe>_parse]`, `[sources.<safe>_source]` component ids
--   * the `<safe>` route key in `[transforms.source_router.route]`
--   * the `<safe>_route` transform fetch parsers bind to via
--     `dispatch_route_name`
--
-- So `My Source`, `my-source` and `My/Source` are three rows the database
-- happily accepts and one file the deploy writes. The last writer wins; if one
-- of the pair is disabled, the deploy loop's disabled branch DELETES the file
-- the enabled one just wrote. Duplicate route keys in one route table make
-- `_router.toml` unparseable, which stops ingestion for the whole tenant
-- rather than for one source. None of it raises an error attributable to the
-- cause.
--
-- Application-level enforcement (with an error message that names the
-- conflicting source) lives in `ParserService::ensure_generated_identity_free`
-- and `SourceConfigService::identity_conflict`. Both are list-then-write and
-- therefore racy on their own; these indexes are the backstop that closes the
-- window between two concurrent creates — the same division of labour as the
-- NAN-883 single-instance check and migration 184.
--
-- NORMALIZATION DIFFERS SLIGHTLY FROM RUST, DELIBERATELY.
-- `safe_name` uses Rust's Unicode-aware `char::is_alphanumeric()`, so `café`
-- survives as `café`. This index uses the ASCII class `[^A-Za-z0-9]`, which
-- also folds `é` to `_`. Two reasons:
--   1. PostgreSQL's `[[:alnum:]]` is locale-dependent and therefore NOT
--      immutable — unusable in an index expression, since a locale change
--      would silently corrupt it. `[^A-Za-z0-9]` is locale-independent.
--   2. TOML bare keys are ASCII-only, so a non-ASCII generated id is already
--      an invalid Vector component id. Being stricter here can only reject a
--      pair that would have been broken anyway.
-- The consequence is that this index rejects a strict SUPERSET of what the
-- Rust check rejects: `Café` alongside `Cafe` passes the service check and is
-- refused by the index as a unique violation. Rare, and the repositories map
-- that violation back to an actionable message.

-- ---------------------------------------------------------------------------
-- Step 1: log_sources (parsers / log sources)
-- ---------------------------------------------------------------------------
--
-- An upgrading tenant may ALREADY hold colliding rows — they were creatable
-- until now, which is the whole point of this ticket. A bare CREATE UNIQUE
-- INDEX would abort the migration and take the deployment down on boot, so
-- the index is created only when the data admits it and the collision is
-- reported otherwise. A tenant left without the index still gets the
-- application-level check (which compares against every existing row), so new
-- collisions are still refused there; only the concurrent-create race stays
-- open until an operator resolves the existing duplicates and creates the
-- index by hand with the statement quoted in the warning.
DO $$
DECLARE
    collisions TEXT;
BEGIN
    SELECT string_agg(detail, '; ' ORDER BY detail)
      INTO collisions
      FROM (
          SELECT lower(regexp_replace(name, '[^A-Za-z0-9]', '_', 'g'))
                 || ' <- ' || string_agg(name, ', ' ORDER BY name) AS detail
            FROM log_sources
           GROUP BY lower(regexp_replace(name, '[^A-Za-z0-9]', '_', 'g'))
          HAVING count(*) > 1
      ) dupes;

    IF collisions IS NULL THEN
        CREATE UNIQUE INDEX IF NOT EXISTS log_sources_generated_vector_identity
            ON log_sources (lower(regexp_replace(name, '[^A-Za-z0-9]', '_', 'g')));

        COMMENT ON INDEX log_sources_generated_vector_identity IS
            'NAN-2305: uniqueness on the GENERATED Vector identifier (safe_name of the display name), which is the parser TOML filename, the transform component ids and the source_router route key. UNIQUE(name) does not cover it: "My Source" and "my-source" are two rows and one file. See ParserService::ensure_generated_identity_free.';
    ELSE
        RAISE WARNING
            'NAN-2305: log_sources already contains names that generate the same Vector identifier, so the uniqueness index was NOT created. These log sources are overwriting each other''s generated config: %. Rename all but one in each group, then run: CREATE UNIQUE INDEX CONCURRENTLY log_sources_generated_vector_identity ON log_sources (lower(regexp_replace(name, ''[^A-Za-z0-9]'', ''_'', ''g'')));',
            collisions;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Step 2: source_configurations (transports)
-- ---------------------------------------------------------------------------
--
-- The stem here is not plain `safe_name(name)`: NAN-940 pins `splunk_hec` to a
-- fixed stem regardless of its display name, so an admin renaming the OOTB row
-- cannot strand its file or break the `splunk_hec_route` transform that HEC
-- parsers hardcode. The index mirrors `SourceConfigService::config_safe_stem`
-- exactly, which also makes it catch the case a name-only comparison misses: a
-- `kafka` config named "Splunk HEC" generates `splunk_hec.toml`, the very file
-- the pinned singleton owns.
DO $$
DECLARE
    collisions TEXT;
BEGIN
    SELECT string_agg(detail, '; ' ORDER BY detail)
      INTO collisions
      FROM (
          SELECT lower(regexp_replace(
                     CASE WHEN config_type = 'splunk_hec' THEN 'splunk_hec' ELSE name END,
                     '[^A-Za-z0-9]', '_', 'g'))
                 || ' <- ' || string_agg(name, ', ' ORDER BY name) AS detail
            FROM source_configurations
           GROUP BY lower(regexp_replace(
                        CASE WHEN config_type = 'splunk_hec' THEN 'splunk_hec' ELSE name END,
                        '[^A-Za-z0-9]', '_', 'g'))
          HAVING count(*) > 1
      ) dupes;

    IF collisions IS NULL THEN
        CREATE UNIQUE INDEX IF NOT EXISTS source_configurations_generated_vector_identity
            ON source_configurations (lower(regexp_replace(
                CASE WHEN config_type = 'splunk_hec' THEN 'splunk_hec' ELSE name END,
                '[^A-Za-z0-9]', '_', 'g')));

        COMMENT ON INDEX source_configurations_generated_vector_identity IS
            'NAN-2305: uniqueness on the GENERATED on-disk stem (SourceConfigService::config_safe_stem), which is the sources/configs TOML filename, the [sources.<stem>_source] block and the <stem>_route transform parsers bind to. Mirrors the NAN-940 pinned stem for splunk_hec so a differently-typed config cannot take it.';
    ELSE
        RAISE WARNING
            'NAN-2305: source_configurations already contains names that generate the same on-disk stem, so the uniqueness index was NOT created. These configurations are overwriting each other''s generated TOML: %. Rename all but one in each group, then create the index by hand (see migration 283).',
            collisions;
    END IF;
END
$$;
