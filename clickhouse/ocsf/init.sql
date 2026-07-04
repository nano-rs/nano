-- =============================================================================
-- nano — Canonical OCSF ClickHouse Schema  (OCSF 1.8.0, Phase 0 / NAN-1242)
-- =============================================================================
--
-- WHAT THIS IS
-- ------------
-- The canonical landing table for events that arrive already shaped as standard
-- OCSF (Open Cybersecurity Schema Framework) records, pinned to OCSF **1.8.0**
-- (the latest *tagged stable* release; 1.9.0 exists only as `1.9.0-dev` on main).
--
-- THE "DROP-IT-IN" / EVENT-AS-SPILL MENTAL MODEL
-- ----------------------------------------------
--   A user drops a *standard OCSF record* into the single `event` JSON column.
--   The matching promoted columns below MATERIALIZE out of it (dotted OCSF field
--   names, e.g. `src_endpoint.ip`, `actor.process.cmd_line`), and the unmapped
--   nested tail simply stays inside `event` — the spill. This is the OCSF analog
--   of UDM's `ext` column, EXCEPT the contrast is important:
--     * UDM: a Vector VRL pipeline parses raw logs into flat `.udm.*` fields and
--       dumps the leftover into `ext`. nano OWNS that parse.
--     * OCSF: the client (or nano, in open-core ingestion) emits a whole standard
--       OCSF object; there is no per-source parse to own. The promoted columns are
--       derived mechanically from the standard shape, and the leftover (the deep
--       nested tail, multi-valued arrays, profile-specific attributes) stays in
--       `event` and resolves lazily via JsonPath (scoping §5).
--
-- DOTTED OCSF COLUMN NAMES  (LOCKED naming convention — NAN-1242)
-- ---------------------------------------------------------------
--   Promoted columns use their LITERAL dotted OCSF field path as the ClickHouse
--   column name — NOT an underscore-flattened alias:
--       `src_endpoint.ip`, `dst_endpoint.port`, `actor.process.cmd_line`,
--       `user.name`, `cloud.account.uid`, ...
--   ClickHouse supports dotted top-level column names when backtick-quoted; they
--   index fine and DO NOT collide with the `event` JSON subcolumns (verified on
--   CH 26.4). Conventions:
--     * Real OCSF scalar field            -> its literal dotted path.
--     * Array-derived value (no scalar     -> `<path>.<derived>` e.g.
--       OCSF path, selected from an array)     `file.hashes.sha256`,
--                                              `actor.process.file.hashes.sha256`,
--                                              `answers.rdata`, `vulnerabilities.cve.uid`,
--                                              `enrichments.<udm_name>`.
--     * Full-text (nano-internal lower()/      -> NO stored column. A text skip
--       tokenized search)                         index is attached to the
--       generator's expression directly
--       (`lower(<col>)`); see the FULL-TEXT SEARCH section below. (The old
--       `<col>.search` companion columns were removed — they were never matched
--       by the query path. NAN-1241 / NAN-1247.)
--     * Enum siblings already top-level     -> unchanged (`activity_id`/`activity`,
--       OCSF (no dot)                          `severity_id`/`severity`,
--                                              `status_id`/`status`).
--   In DDL these names MUST be backtick-quoted, including in skip-index refs:
--       `src_endpoint.ip` String MATERIALIZED ...
--       INDEX idx_x `src_endpoint.ip` TYPE bloom_filter ...
--
-- THE INGESTION CONTRACT  (read this before you touch the table)
-- --------------------------------------------------------------
--   The client inserts ONLY two things:
--       1. `event`     — the full, standard OCSF JSON record (the entire object).
--       2. `timestamp` — the row's event time as DateTime64(3,'UTC').
--                        (See "WHY timestamp IS NOT MATERIALIZED" below.)
--   Direct (no-Vector) writers: the full producer-facing contract — required
--   fields, the INSERT-only `nanosiem_ingest` credential, the lowercase
--   `source_type` rule, and the bad-`time` fallback semantics — lives in
--   docs/user-guide/direct-ocsf-ingestion.md (NAN-1384).
--
--   EVERYTHING ELSE on this table is a MATERIALIZED column derived from `event`
--   at INSERT time via JSONExtract*, plus server-side skip indexes. Because the
--   columns are MATERIALIZED, the client cannot (and must not) write them.
--   ClickHouse computes them from `event` on every INSERT. This keeps the wire
--   format dead simple (one JSON blob) and lets us re-derive / re-index the hot
--   columns purely by editing this DDL — no client change required.
--
-- ENRICHMENT IS DUAL-MODE  (NOT read-only — important)
-- ----------------------------------------------------
--   Enrichment columns (`*.location.*`, `*.autonomous_system.*`, `cloud.*`,
--   `enrichments.*`) populate from OCSF-NATIVE fields REGARDLESS of who computed
--   them:
--     * When nano OWNS ingestion (open-core + Vector), nano computes geo/ASN/IOC
--       and writes them INTO the standard OCSF objects (src_endpoint.location,
--       src_endpoint.autonomous_system, the enrichments[] array) before the row
--       lands — so the promoted columns materialize from those native fields.
--     * When the client ships PRE-ENRICHED OCSF, the same native fields are
--       already present and the same promoted columns materialize from them.
--   Either way the enrichment lives in standard OCSF shape and is promoted +
--   indexed here. (Contrast UDM, where enrichment is dictGet against dicts nano
--   provisions at insert time.) The enrichments[] array is keyed BY NAME: each
--   entry's `name` is the UDM column it corresponds to (e.g. an entry named
--   "ioc_src_ip_threat_type"), selected via arrayFirst(... name = '<udm>' ...).
--
-- MAPPING SOURCE OF TRUTH
-- -----------------------
--   nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json. This DDL is the
--   mechanical realization of that manifest; the two are gated in lock-step by
--   tests/ocsf_manifest_ddl_consistency.rs. `activity_id` is shared between the
--   taxonomy entry and `file_action`.
--
-- INDEX / lower() / PREWHERE PARITY WITH UDM `logs`
-- -------------------------------------------------
--   Promoted columns mirror their UDM `logs` counterparts:
--     * IPs are String (not CH-native IPv4) so IPv4+IPv6 are handled uniformly
--       and the bloom/PREWHERE/lower() optimizer hints match UDM byte-for-byte.
--     * Host / user / domain / IP / MAC / email columns are lowercase-normalized
--       in the MATERIALIZED expression so the SQL generator's
--       LOWERCASE_NORMALIZED_FIELDS fast-path applies unchanged.
--     * Numeric fields (ports, bytes, packets, pids, enum *_id ints, ASN number,
--       http status) are never lower()'d — they are integer columns.
--     * Hashes are lower()'d to match UDM's hash dict-key convention.
--
-- WHY `timestamp`, `class_uid` AND `src_endpoint.ip` ARE NOT MATERIALIZED
-- ------------------------------------------------------------------------
--   ClickHouse forbids MATERIALIZED columns in the sort key / partition key
--   (scoping §2.4). The table must be ordered & partitioned on event time, so
--   `time_dt` (OCSF `time`) CANNOT be MATERIALIZED. We therefore expose event
--   time as a plain `timestamp DateTime64(3,'UTC')` column that the client
--   writes directly, and we DEFAULT-derive it from `event` as a safety net for
--   clients that omit it. OCSF `time` is epoch **milliseconds** (timestamp_t),
--   so we convert with `fromUnixTimestamp64Milli(event.time)` — NEVER compare a
--   raw ms int against DateTime64 (it coerces as *seconds* → year ~57000; this
--   was the NAN-1123 footgun). `time_dt` remains in the manifest as the logical
--   name; here it is the physical `timestamp` column (documented alias below).
--   NAN-1334 EXTENDS this carve-out to `class_uid` and `src_endpoint.ip`: both
--   now sit in the sort key (see SORT-KEY DECISION) and so they too are flipped
--   from MATERIALIZED to DEFAULT — same expression, same type, same CODEC, but
--   sort-key-legal. DEFAULT (unlike MATERIALIZED) means a client MAY write them
--   and they appear in SELECT *; the DEFAULT expression still derives from
--   `event` for any producer that ships only the blob, so the "just send the
--   blob" wire contract is unchanged. The tradeoff — a client-supplied value is
--   used as-is and CAN diverge from `event` — is the same one already accepted
--   for `timestamp`.
--
-- ENUM FIELDS
-- -----------
--   OCSF enums carry an `_id` int + a sibling display string. We materialize
--   BOTH: filter on the int (selective, indexed), display the string. Pairs:
--     activity_id / activity, severity_id / severity,
--     status_id / status, auth_protocol_id / auth_protocol.
--
-- ARRAY-KEYED / ARRAY-DERIVED FIELDS
-- ----------------------------------
--   * Hashes: OCSF `file.hashes[]`, `process.file.hashes[]` (SUBJECT process) and
--     `actor.process.file.hashes[]` (PARENT process) are `fingerprint[]` arrays of
--     {algorithm_id, value}. SHA-256 == algorithm_id 3 (verified from
--     objects/fingerprint.json). We pull the SHA-256 element with
--     arrayFirst(... algorithm_id = 3 ...) and lower() it → `*.hashes.sha256`.
--     UDM process_hash maps to the SUBJECT `process.file.hashes.sha256`.
--   * DNS answers: `answers[]` is dns_answer[]; we take the first element's
--     `rdata` → `answers.rdata` (UDM `answer`).
--   * Email recipients: `email.to[]` is an email-address array (scalar strings);
--     we take the first element → `email.to` (UDM recipient).
--   * Vulnerabilities: `vulnerabilities[]` is a vulnerability[] (Finding classes);
--     we take the first element's nested `cve.uid` → `vulnerabilities.cve.uid`
--     (UDM cve).
--   * Enrichments: `enrichments[]` is an enrichment[] of {name,value,...}; we
--     select BY NAME — arrayFirst(... name = '<udm col>' ...).value (dual-mode,
--     see above).
--
-- TARGET CH VERSION & CAVEATS
-- ---------------------------
--   * Validated against ClickHouse **26.4** (the `JSON` type is GA in 26.x; on
--     older 24.x builds it required `SET allow_experimental_object_type=1` /
--     `enable_json_type=1`. On 26.4 no experimental flag is needed.)
--   * Dotted backtick-quoted column names coexist with `event` JSON subcolumns
--     (verified: they index fine and do not collide).
--   * `event` is declared `JSON(max_dynamic_paths = 1024)` mirroring the UDM
--     `ext JSON(max_dynamic_paths=512)` idiom — wider because a full OCSF record
--     has far more paths than the UDM `ext` overflow blob.
--   * JSONExtract* over a `JSON`-typed column does NOT read dynamic subpaths —
--     it re-serializes the ENTIRE event object per row (empirically confirmed on
--     CH 26.4: 87–300x more read_bytes than subcolumn access, NAN-1426). Query
--     codegen therefore emits native subcolumn access (`event."a"."b"`, with
--     `event.^"a"."b"` for object subtrees) for scalar/leaf reads; this DDL's
--     MATERIALIZED expressions still use JSONExtract forms (one-time ingest
--     cost, not per-query). Arrays are pulled with
--     JSONExtractArrayRaw(JSONExtractRaw(...)) then filtered.
--   * `time` precision is ms → DateTime64(**3**) (UDM `logs` uses (6) for micros;
--     OCSF only carries ms, so (3) is correct and avoids fake precision).
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_raw
(
    -- NAN-1443: implicit-insertable derivation source for the Null-table + MV
    -- pattern. `event` is a NORMAL column here (NOT ephemeral) so ClickHouse's
    -- implicit (no-column-list) INSERT — what the Vector clickhouse sink emits —
    -- populates it. ENGINE = Null stores nothing; the ocsf_logs_raw_mv reads each
    -- inserted block, derives every promoted column, and writes the result to
    -- nanosiem.ocsf_logs. Both ingest paths still write only (event, source_type)
    -- [+ optional timestamp/id]; the INSERT contract is unchanged.
    `event` JSON(max_dynamic_paths = 1024) DEFAULT '{}' CODEC(ZSTD(3)),
    -- Derive timestamp from event.time when a direct writer omits it (Vector always
    -- provides it). EXACT multiIf carried over from the old ocsf_logs.timestamp DEFAULT.
    `timestamp` DateTime64(3, 'UTC')
        DEFAULT multiIf(
            toInt64OrZero(JSONExtractString(event, 'time')) >= 100000000000000,
                fromUnixTimestamp64Milli(intDiv(toInt64OrZero(JSONExtractString(event, 'time')), 1000), 'UTC'),
            toInt64OrZero(JSONExtractString(event, 'time')) >= 10000000000,
                fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(event, 'time')), 'UTC'),
            toInt64OrZero(JSONExtractString(event, 'time')) > 0,
                fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(event, 'time')) * 1000, 'UTC'),
            parseDateTime64BestEffortOrZero(JSONExtractString(event, 'time'), 3, 'UTC') != toDateTime64(0, 3, 'UTC'),
                parseDateTime64BestEffortOrZero(JSONExtractString(event, 'time'), 3, 'UTC'),
            now64(3, 'UTC')
        ),
    `source_type` LowCardinality(String) DEFAULT 'unknown',
    `id` UUID DEFAULT generateUUIDv7()
)
ENGINE = Null
;

-- =============================================================================
-- NATIVE-PROTOCOL ENTRYPOINT  (nanosiem.ocsf_logs_native_raw — Null -> forward)
-- =============================================================================
-- NAN-1603: Tenzir's native `to_clickhouse` operator (v6.4.0+) CAN write to a
-- ClickHouse `JSON` column, but its append mode validates EVERY column type on
-- the target table — even DEFAULT columns the writer never sends — and rejects
-- `LowCardinality(String)` and timezone-qualified `DateTime64(3, 'UTC')`. Both
-- live on ocsf_logs_raw (source_type, timestamp), so to_clickhouse cannot target
-- it directly. This thin entrypoint exposes ONLY to_clickhouse-compatible types
-- (plain `String`, native `JSON`); its MV forwards (event, source_type) into
-- ocsf_logs_raw, where the timestamp/id DEFAULTs fill in and ocsf_logs_raw_mv
-- performs all promotion. ClickHouse cascades MVs through the Null table, so the
-- full chain runs exactly as the HTTP path — no derivation is duplicated. Same
-- wire shape as every direct writer: {event, source_type}.
CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_native_raw
(
    `event` JSON DEFAULT '{}',
    `source_type` String DEFAULT 'unknown'
)
ENGINE = Null
;

-- =============================================================================
-- STORAGE TABLE  (nanosiem.ocsf_logs — MergeTree; MV-populated promoted columns)
-- =============================================================================
-- NAN-1443: every promoted column below is now a PLAIN column populated by
-- nanosiem.ocsf_logs_raw_mv (which derives it from the `event` JSON on the Null
-- staging table nanosiem.ocsf_logs_raw). The `*_unified` and `prevalence_*`
-- columns stay MATERIALIZED here — they derive from the PLAIN promoted columns
-- the MV inserts, not from `event`. The PARTITION BY / ORDER BY / TTL / SETTINGS
-- and all skip indexes are byte-identical to the pre-NAN-1443 single-table form.
CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs
(
    -- -------------------------------------------------------------------------
    -- NO `event` COLUMN (NAN-1443 Null-table + MV pattern).
    -- -------------------------------------------------------------------------
    -- `event` is NOT stored here. It is a normal column on nanosiem.ocsf_logs_raw
    -- (ENGINE = Null); nanosiem.ocsf_logs_raw_mv derives every promoted column
    -- below from it and inserts the result here. The unpromoted spill is persisted
    -- in `unmapped`; the full OCSF envelope is reconstructed on demand from the
    -- promoted columns + `message` + `unmapped`.

    -- -------------------------------------------------------------------------
    -- SORT / PARTITION KEY  (client-written DEFAULT; CANNOT be MATERIALIZED — see
    -- header. `class_uid` + `src_endpoint.ip` join this carve-out under NAN-1334.)
    -- -------------------------------------------------------------------------
    -- Logical manifest name: `time_dt`. Physical name: `timestamp` (kept in line
    -- with UDM `logs.timestamp` so shared query/codegen treats both tables the
    -- same). DEFAULT derives from event.time (epoch ms) when the client omits it.
    --
    -- NAN-1384 (G17): the original DEFAULT was a bare
    -- `fromUnixTimestamp64Milli(toInt64OrZero(...))`, so a missing / RFC3339 /
    -- epoch-SECONDS / otherwise non-ms `time` derived 1970 — and the 365d row
    -- TTL then annihilated the row at part-write while the INSERT returned
    -- HTTP 200. Direct writers (no Vector `now()` fallback) lost rows silently.
    -- The DEFAULT now NEVER yields 1970: spec-conformant epoch-ms passes through
    -- unchanged, common nonconformant shapes are repaired, and everything else
    -- falls back to insert time:
    --   * >= 1e14            -> epoch MICROSECONDS (÷1000; would otherwise
    --                           overflow DateTime64(3)'s 2299 ceiling)
    --   * >= 1e10            -> epoch MILLISECONDS (the OCSF timestamp_t spec
    --                           shape; 1e10 ms = 2001-09-09, so every real
    --                           event-time lands here)
    --   * > 0                -> epoch SECONDS (×1000; the most common
    --                           real-world pipeline mistake)
    --   * RFC3339/ISO string -> parseDateTime64BestEffortOrZero
    --   * anything else      -> now64(3) (missing, garbage, negative)
    -- The Vector lane always writes `timestamp` explicitly, so this DEFAULT only
    -- fires on the direct-write path. See also the TTL guard at the bottom of
    -- this CREATE and docs/user-guide/direct-ocsf-ingestion.md.
    `timestamp` DateTime64(3, 'UTC') CODEC(Delta(8), ZSTD(3)),
    -- Manifest alias: queries written against `time_dt` resolve to `timestamp`.
    `time_dt` DateTime64(3, 'UTC') ALIAS timestamp,
    -- Bookkeeping (parity with UDM logs minmax-indexed insert clock).
    `_inserted_at` DateTime64(3, 'UTC') DEFAULT now64(3) CODEC(Delta(8), ZSTD(3)),
    -- -------------------------------------------------------------------------
    -- SERVER-OWNED ROW IDENTITY  (NAN-1241)
    -- -------------------------------------------------------------------------
    -- Stable per-row key for the UI's fetch-by-id (row expand / event inspector).
    -- OCSF carries no GUARANTEED unique key: `metadata.uid` is spec-OPTIONAL and
    -- frequently unset (our own parsers, a Cribl pipeline, or a BYO-ClickHouse
    -- producer may all omit it), so the UI cannot key on it. We mint identity
    -- server-side at insert, exactly like UDM `logs.id`: any producer that inserts
    -- only `event` gets a stable id for free, and a producer with its own key may
    -- insert `id` explicitly to override. `metadata.uid` stays the OCSF-native
    -- semantic/correlation id (promoted column) — deliberately distinct from this
    -- physical row key. Mirrors UDM `logs.id` (UUIDv7 + ZSTD(3)) byte-for-byte.
    `id` UUID CODEC(ZSTD(3)),
    -- -------------------------------------------------------------------------
    -- OPERATIONAL PROVENANCE KEY  (Security Lake "custom source" pattern)
    -- -------------------------------------------------------------------------
    -- `source_type` is the ergonomic ingest-routing identity (e.g. 'apache') —
    -- the same value the Vector router keys on, written by INGESTION from the
    -- `X-Source-Type` header and lowercased at ingest. It is NOT part of the OCSF
    -- `event` record and is NOT MATERIALIZED / manifest-promoted: the OCSF `event`
    -- stays 100% pure. It lives here, next to `timestamp`/`_inserted_at`, as a
    -- plain client/ingest-written column so analysts can lead a hunt with the
    -- fast `source_type=apache` first-filter. Mirrors UDM `logs.source_type`
    -- byte-for-byte (LowCardinality + DEFAULT 'unknown' + set(100) skip index).
    --
    -- NAN-1384 (G18): the direct-write contract REQUIRES lowercase values, but a
    -- client-written DEFAULT column cannot be normalized server-side (DEFAULT
    -- only fires when the column is omitted; MATERIALIZED is not client-
    -- writable). A MixedCase direct write used to produce filter-invisible rows
    -- because the generator's lowercase-normalized fast-path compared the stored
    -- value verbatim. The OCSF profile therefore no longer claims `source_type`
    -- as lowercased-at-ingest — queries emit `lower(source_type) = '...'`
    -- (dictionary-evaluated on LowCardinality, so effectively free) and
    -- nonconformant rows stay findable. UDM keeps its fast-path: its ingestion
    -- is exclusively Vector-owned, which lowercases at the edge.
    `source_type` LowCardinality(String) CODEC(ZSTD(1)),

    -- =========================================================================
    -- TAXONOMY  (numeric event-kind discriminators; PREWHERE-eligible)
    -- =========================================================================
    -- OCSF class (3002 Authentication, 4001 Network Activity, 1007 Process
    -- Activity, 1001 File System Activity). Replaces UDM source_type as the
    -- per-source discriminator. Leads the sort key — so it is DEFAULT (NOT
    -- MATERIALIZED), as CH forbids MATERIALIZED columns in the sort key. The
    -- DEFAULT expression still derives it from `event` (NAN-1334).
    `class_uid` UInt32 CODEC(T64, ZSTD(1)),
    -- Coarser category (1=System, 3=IAM, 4=Network).
    `category_uid` UInt32 CODEC(T64, ZSTD(1)),
    -- Class-scoped activity enum (Auth 1=Logon; File 1=Create/4=Delete/...).
    -- ALSO serves UDM `file_action` on class_uid=1001 (manifest: file_action has
    -- no own column — it is activity_id scoped by class).
    `activity_id` UInt32 CODEC(T64, ZSTD(1)),
    -- Sibling display string for activity_id (UDM action analog). Emitters
    -- serialize it as `activity_name`; nano-internal sibling label = `activity`.
    `activity` String CODEC(ZSTD(1)),
    -- Most-specific id: type_uid = class_uid*100 + activity_id. long_t -> UInt64.
    `type_uid` UInt64 CODEC(T64, ZSTD(1)),
    -- Severity enum int (0=Unknown,1=Info..6=Fatal,99=Other).
    `severity_id` UInt8 CODEC(T64, LZ4),
    -- Sibling severity string (mirrors UDM severity LowCardinality + set index).
    `severity` LowCardinality(String) CODEC(ZSTD(1)),

    -- =========================================================================
    -- CORE OUTCOME / MESSAGE
    -- =========================================================================
    -- Generic outcome enum (0=Unknown,1=Success,2=Failure,99=Other). UDM
    -- auth_result / status. status_id is canonical for filtering.
    `status_id` UInt32 CODEC(T64, ZSTD(1)),
    -- Sibling status string (UDM status; set-indexed).
    `status` LowCardinality(String) CODEC(ZSTD(1)),
    -- Human-readable summary; the primary full-text hunt field (text index).
    `message` String CODEC(ZSTD(3)),
    -- The OCSF `unmapped` spill — producer source fields that did not map to a
    -- standard OCSF attribute (the OCSF analog of UDM's `ext`). This is the ONLY
    -- part of the arriving `event` we persist verbatim (NAN-1443): everything else
    -- is a promoted column, so the full `event` is never stored. Unpromoted tail
    -- reads (`ext.*` / `unmapped.*` / bare non-promoted tokens) resolve here via
    -- native subcolumn access; `event.^unmapped` extracts the sub-object (a clean
    -- `{}` when the producer emitted no unmapped key). It IS the OCSF profile's
    -- `json_tail_column` (NAN-1443; was `event`).
    `unmapped` JSON(max_dynamic_paths = 512) CODEC(ZSTD(3)),

    -- =========================================================================
    -- NETWORK  (endpoints, ports, MACs, traffic, protocol)
    -- =========================================================================
    -- Initiator IP. String (handles v4+v6); lowercase-normalized like UDM src_ip.
    -- Part of the sort key (NAN-1334: clusters a hot IP into few granules so the
    -- bloom prunes), so it is DEFAULT (NOT MATERIALIZED) — CH forbids MATERIALIZED
    -- columns in the sort key. Same lower(JSONExtract...) derivation from `event`.
    `src_endpoint.ip` String CODEC(ZSTD(1)),
    -- Responder IP.
    `dst_endpoint.ip` String CODEC(ZSTD(1)),
    -- Ports: port_t -> UInt16 (NUMERIC, never lower()'d).
    `src_endpoint.port` UInt16 CODEC(T64, LZ4),
    `dst_endpoint.port` UInt16 CODEC(T64, LZ4),
    -- MACs (network_endpoint.mac). UDM src_mac/dest_mac parity (bloom). lower()'d.
    `src_endpoint.mac` String CODEC(ZSTD(1)),
    `dst_endpoint.mac` String CODEC(ZSTD(1)),
    -- Initiator hostname (primary src_host source). lowercase-normalized.
    `src_endpoint.hostname` LowCardinality(String) CODEC(ZSTD(1)),
    -- Host-context hostname: fallback src_host for endpoint-centric classes
    -- (Process/File) where there is no src_endpoint. Profile may
    -- COALESCE(`src_endpoint.hostname`, `device.hostname`).
    `device.hostname` LowCardinality(String) CODEC(ZSTD(1)),
    -- Responder hostname (UDM dest_host parity).
    `dst_endpoint.hostname` LowCardinality(String) CODEC(ZSTD(1)),
    -- IANA protocol number (integer_t, -1 unknown -> Int32). UDM `protocol`
    -- string is surfaced via profile mapping, not a separate hot column.
    `connection_info.protocol_num` Int32 CODEC(T64, ZSTD(1)),
    -- Traffic counters: long_t -> UInt64 (NUMERIC).
    `traffic.bytes_in` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.bytes_out` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.packets_in` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.packets_out` UInt64 CODEC(T64, ZSTD(1)),

    -- =========================================================================
    -- IDENTITY  (class-dependent subject vs actor — both promoted)
    -- =========================================================================
    -- For Authentication 3002 / IAM the SUBJECT is top-level `user.name`.
    -- lowercase-normalized like UDM user. Profile resolves UDM `user` to
    -- COALESCE(`user.name`, `actor.user.name`) per-class.
    `user.name` String CODEC(ZSTD(1)),
    -- The INITIATOR / actor user (UDM src_user; fallback for `user` in endpoint
    -- classes). lowercase-normalized.
    `actor.user.name` String CODEC(ZSTD(1)),
    -- user.domain (UDM user_domain; lowercase-normalized — skips lower() wrapper).
    `user.domain` String CODEC(ZSTD(1)),
    -- user.uid: OCSF string_t (SID/UPN/objectGUID) — opaque String, not numeric.
    `user.uid` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- PROCESS  (OCSF role model: `process` = SUBJECT, `actor.process` = PARENT)
    -- =========================================================================
    -- Per OCSF Process Activity 1007: top-level `process` (required) is the
    -- SUBJECT — the process that was launched / injected / terminated / etc. The
    -- `actor.process` is the PARENT / initiator that acted on it. So the PRIMARY
    -- UDM columns (process_name / command_line / process_id / process_guid /
    -- process_hash) promote out of `process.*`, and `actor.process.*` is the
    -- PARENT (UDM parent_command_line). Both are promoted; UDM resolution picks the
    -- subject by default (was inverted before NAN-1241 process-role fix).
    --
    -- SUBJECT (process.*) — the PRIMARY UDM process columns ("what ran").
    -- process.name — UDM process_name.
    `process.name` String CODEC(ZSTD(1)),
    -- process.cmd_line — UDM command_line. OCSF uses `cmd_line` (not command_line).
    `process.cmd_line` String CODEC(ZSTD(1)),
    -- process.pid (integer_t -> UInt32, NUMERIC) — UDM process_id.
    `process.pid` UInt32 CODEC(T64, LZ4),
    -- process.uid — OCSF-native process identifier (process_t.uid). The OCSF
    -- analog of UDM process_guid; promoted directly (NOT recomputed). bloom for
    -- process-tree pivots.
    `process.uid` String CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: process.file.hashes[] is fingerprint[]; pick algorithm_id=3
    -- (SHA-256) -> .value, lowercased (UDM hash dict-key conv). UDM process_hash.
    -- arrayFirst over the parsed JSON array selects the SHA-256 element; if none
    -- present arrayFirst returns '' (default of the inner extracted type).
    `process.file.hashes.sha256` String CODEC(ZSTD(3)),
    -- process.file.path — SUBJECT process image path (Process Activity 1007).
    -- UDM process_path. Not lower()'d (paths preserve case, like file.path). Text
    -- skip index for path-fragment hunts.
    `process.file.path` String CODEC(ZSTD(1)),
    -- PARENT / INITIATOR (actor.process.*) — UDM parent_command_line + parent pivots.
    -- actor.process.name — PARENT process name (no UDM scalar; pivots/hunts).
    `actor.process.name` String CODEC(ZSTD(1)),
    -- actor.process.cmd_line — PARENT cmd line == UDM parent_command_line.
    `actor.process.cmd_line` String CODEC(ZSTD(1)),
    -- actor.process.pid — PARENT process pid (integer_t -> UInt32, NUMERIC).
    `actor.process.pid` UInt32 CODEC(T64, LZ4),
    -- actor.process.uid — PARENT process uid (process_t.uid). bloom for pivots.
    `actor.process.uid` String CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: actor.process.file.hashes[] is fingerprint[]; pick
    -- algorithm_id=3 (SHA-256) -> .value, lowercased. PARENT process hash
    -- (parent-hash pivots + prevalence summary). arrayFirst over the parsed JSON
    -- array selects the SHA-256 element; '' when none present.
    `actor.process.file.hashes.sha256` String CODEC(ZSTD(3)),
    -- actor.process.file.path — PARENT/INITIATOR process image path; also the
    -- acting-process image on module/network/file/dns/registry classes. UDM
    -- parent_process_path. Not lower()'d. Text skip index for path-fragment hunts.
    `actor.process.file.path` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- FILE  (File System Activity 1001 target object)
    -- =========================================================================
    `file.name` String CODEC(ZSTD(1)),
    `file.path` String CODEC(ZSTD(1)),
    -- module.file.path — loaded module image path (Module Activity 1005).
    -- OCSF-native; no UDM equivalent. Not lower()'d. Text skip index.
    `module.file.path` String CODEC(ZSTD(1)),
    -- module.file.name — loaded module file name (Module Activity 1005). bloom.
    `module.file.name` String CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: file.hashes[] is fingerprint[]; SHA-256 (algorithm_id=3).
    -- There is NO scalar file_hash in OCSF. Lowercased.
    `file.hashes.sha256` String CODEC(ZSTD(3)),

    -- =========================================================================
    -- AUTHENTICATION  (Authentication 3002)
    -- =========================================================================
    -- Auth protocol enum int (1=NTLM,2=Kerberos,5=SAML,6=OAUTH2,...,99=Other).
    `auth_protocol_id` UInt32 CODEC(T64, ZSTD(1)),
    -- Sibling auth protocol string (display; auth_protocol_id is canonical).
    `auth_protocol` LowCardinality(String) CODEC(ZSTD(1)),
    -- session.uid (UDM session_id).
    `session.uid` String CODEC(ZSTD(1)),
    -- is_mfa — OCSF boolean_t (Authentication 3002, recommended); whether MFA was
    -- used. UDM mfa_used (boolean -> UInt8 0/1). NUMERIC (never lower()'d). No skip
    -- index: a 2-value boolean is non-selective, mirroring UDM mfa_used (no index).
    `is_mfa` UInt8 CODEC(T64, LZ4),

    -- =========================================================================
    -- WEB  (top-level `url` object — Network Activity 4001, NOT HTTP 4002)
    -- =========================================================================
    -- The top-level `url` object is carried by Network Activity 4001 (and other
    -- classes that embed a url object). HTTP Activity 4002 has NO top-level `url` —
    -- its URL lives at `http_request.url.*` (promoted in the HTTP section below).
    -- So these columns serve 4001; the UDM url_domain/url aliases resolve to the
    -- HTTP `http_request.url.*` columns (fixed in the NAN-1241 HTTP-url placement).
    -- url.hostname == the network-activity domain (IOC/prevalence pivot entity).
    `url.hostname` String CODEC(ZSTD(1)),
    -- url.url_string == full URL string for 4001. OCSF 1.8.0 uses `url_string`
    -- (the prior manifest's `url.text` was wrong — `text` is not a url attr).
    `url.url_string` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- HTTP ACTIVITY  (class 4002 — URL lives under http_request.url, not top-level)
    -- =========================================================================
    -- http_request.http_method (GET/POST/...). UDM http_method (set index).
    `http_request.http_method` LowCardinality(String) CODEC(ZSTD(1)),
    -- http_request.url.hostname — HTTP request URL domain. HTTP 4002 has no
    -- top-level url, so THIS is the UDM url_domain for HTTP (bloom; domain entity).
    -- NOT lower()'d (matches the top-level url.hostname convention).
    `http_request.url.hostname` String CODEC(ZSTD(1)),
    -- http_request.url.url_string — full HTTP request URL. HTTP 4002 has no
    -- top-level url, so THIS is the UDM url for HTTP (text index, URL-fragment hunts).
    `http_request.url.url_string` String CODEC(ZSTD(1)),
    -- http_request.url.path — requested path component (URL-fragment hunt field).
    `http_request.url.path` String CODEC(ZSTD(1)),
    -- http_request.user_agent. UDM http_user_agent (tokenized UA hunts).
    `http_request.user_agent` String CODEC(ZSTD(1)),
    -- http_response.code (HTTP status int -> UInt16). UDM http_status_code.
    `http_response.code` UInt16 CODEC(T64, LZ4),
    -- NAN-1465: UDM-parity promotions — registry forensics (sysmon), web
    -- referrer + content category, AWS principal identity, base-event duration.
    `reg_key.path` String CODEC(ZSTD(1)),
    `reg_value.name` String CODEC(ZSTD(1)),
    `reg_value.path` String CODEC(ZSTD(1)),
    `reg_value.data` String CODEC(ZSTD(1)),
    `http_request.referrer` String CODEC(ZSTD(1)),
    `http_request.url.categories` Array(String) DEFAULT [] CODEC(ZSTD(1)),
    `actor.user.uid` String CODEC(ZSTD(1)),
    `actor.user.type` LowCardinality(String) CODEC(ZSTD(1)),
    `duration` UInt32 CODEC(T64, LZ4),

    -- =========================================================================
    -- DNS ACTIVITY  (class 4003)
    -- =========================================================================
    -- query.hostname — queried domain (UDM query; domain entity + tokenized).
    `query.hostname` String CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: answers[] is dns_answer[]; take the FIRST element's rdata
    -- (UDM answer). answers may be empty -> '' (default). bloom.
    `answers.rdata` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- EMAIL ACTIVITY  (class 4009)
    -- =========================================================================
    -- email.from (single email_t). UDM sender. lowercase-normalized.
    `email.from` String CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: email.to[] is an email-address array of SCALAR strings;
    -- take the FIRST recipient (UDM recipient). lowercase-normalized.
    -- arrayElement over the raw JSON array yields a quoted JSON string; pull it
    -- through JSONExtractString to strip the quotes before lower().
    `email.to` String CODEC(ZSTD(1)),
    -- email.subject (UDM subject; tokenized).
    `email.subject` String CODEC(ZSTD(1)),
    -- email.message_uid — RFC5322 Message-ID (UDM message_id). bloom.
    -- (email.uid is the THREAD id — different concept, left in tail.)
    `email.message_uid` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- FINDING  (vulnerabilities[] — Finding classes, e.g. 2002)
    -- =========================================================================
    -- ARRAY-DERIVED: vulnerabilities[] is a vulnerability[]; take the FIRST
    -- element's nested cve.uid (UDM cve, e.g. CVE-2021-12345). bloom. Non-finding
    -- events leave this empty. Multi-CVE tail stays in event.
    `vulnerabilities.cve.uid` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- CLOUD  (cloud object — Cloud profile; DUAL-MODE enrichment)
    -- =========================================================================
    -- cloud.provider (required). UDM cloud_provider (set index).
    `cloud.provider` LowCardinality(String) CODEC(ZSTD(1)),
    -- cloud.account.uid (account/subscription id). UDM cloud_account_id (bloom).
    `cloud.account.uid` String CODEC(ZSTD(1)),
    -- cloud.account.name. UDM cloud_account_name (set index).
    `cloud.account.name` LowCardinality(String) CODEC(ZSTD(1)),
    -- cloud.region. UDM cloud_region (set index).
    `cloud.region` LowCardinality(String) CODEC(ZSTD(1)),

    -- =========================================================================
    -- CLOUD API ACTIVITY  (API Activity 6003 — `api` object + resources[])
    -- =========================================================================
    -- api.service is a Service object (objects/api -> objects/service); service.name
    -- is the targeted cloud/AWS service (e.g. 'signin','sts','s3'). UDM cloud_service
    -- (set index). Distinct from cloud.provider (the CSP) and api.operation (the verb).
    `api.service.name` LowCardinality(String) CODEC(ZSTD(1)),
    -- api.operation is the AWS API verb (e.g. 'CreateAccessKey','AssumeRole',
    -- 'AttachUserPolicy') the call invoked. NO UDM equivalent (the cloud action
    -- allow-lists reference this native column directly under OCSF). Distinct from
    -- the generic `activity` (Create/Read/Update/Delete) and api.service.name (target).
    `api.operation` LowCardinality(String) CODEC(ZSTD(1)),
    -- ARRAY-DERIVED: resources[] is a resource_details[] array; take the FIRST
    -- element's sub-field (mirrors the vulnerabilities[].cve.uid pattern:
    -- arrayElement(JSONExtractArrayRaw(JSONExtractRaw(... 'resources')), 1) then the
    -- nested attribute). UDM resource_type/resource_id/resource_name. Multi-resource
    -- tail stays in event. `type` is the source-defined resource type (set index);
    -- `uid`/`name` are bloom (resource-pivot entities). Column names = array-derived
    -- `resources.<attr>`.
    `resources.type` LowCardinality(String) CODEC(ZSTD(1)),
    `resources.uid` String CODEC(ZSTD(1)),
    `resources.name` String CODEC(ZSTD(1)),
    -- NOTE: UDM `change_type` has NO own column — on API Activity 6003 the change
    -- action is the shared `activity_id` (Create=1/Read=2/Update=3/Delete=4), the
    -- same column as the taxonomy/file_action entries. The query layer translates
    -- the enum int <-> UDM change_type string with a LOSSY mapping (create/update/
    -- delete only; UDM 'permission_change' is unrepresentable here). See manifest.

    -- =========================================================================
    -- ENRICHMENT — GEO / ASN  (DUAL-MODE; OCSF-native location/autonomous_system)
    -- =========================================================================
    -- DUAL-MODE: event-native OCSF value first, else dictGet via
    -- nanosiem.ip_enrichment_dict — parity with the UDM `logs` enriched_* columns.
    -- location.country is the ISO 3166-1 Alpha-2 CODE -> UDM enriched_*_country_code
    -- (NOT the name column). location.continent is the continent NAME.
    --
    -- DUAL-MODE: prefer the EVENT-NATIVE OCSF value (client pre-enriched into the
    -- standard location/autonomous_system objects); else compute via the SAME
    -- nanosiem.ip_enrichment_dict the UDM `logs` table uses, keyed on the promoted
    -- src/dst IP (see clickhouse/init.sql enriched_*_country_code / _asn / _as_name).
    -- This is what lets nano-OWNED OCSF ingestion enrich rows that arrive un-enriched.
    -- The dict `asn` attribute is a String like "AS13335" -> strip non-digits + parse
    -- for the numeric autonomous_system.number column.
    `src_endpoint.location.country` LowCardinality(String) CODEC(ZSTD(1)),
    `src_endpoint.location.continent` LowCardinality(String) CODEC(ZSTD(1)),
    -- autonomous_system.number is a numeric ASN (integer_t -> UInt32). UDM
    -- enriched_src_asn (String) surfaced via profile mapping. NUMERIC.
    `src_endpoint.autonomous_system.number` UInt32 CODEC(T64, ZSTD(1)),
    `src_endpoint.autonomous_system.name` String CODEC(ZSTD(1)),
    `dst_endpoint.location.country` LowCardinality(String) CODEC(ZSTD(1)),
    `dst_endpoint.location.continent` LowCardinality(String) CODEC(ZSTD(1)),
    `dst_endpoint.autonomous_system.number` UInt32 CODEC(T64, ZSTD(1)),
    `dst_endpoint.autonomous_system.name` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- ENRICHMENT — IOC / CUSTOM  (DUAL-MODE; OCSF-native enrichments[] BY NAME)
    -- =========================================================================
    -- DUAL-MODE: event-native enrichments[] value first, else dictGet via
    -- nanosiem.{ioc,custom}_enrichment_dict — parity with the UDM `logs` ioc_*/
    -- custom_* columns.
    -- Each promoted column selects the enrichments[] entry whose `name` equals
    -- the UDM column it maps to, then takes its `value`. arrayFirst over the
    -- parsed enrichments[] JSON; '' when no matching entry. This is the generic
    -- by-NAME selector (string key), distinct from the algorithm_id (int key)
    -- selector used for hashes.
    --
    -- DUAL-MODE: prefer the EVENT-NATIVE enrichments[] value (client pre-enriched);
    -- else compute via the SAME dicts the UDM `logs` table uses at insert
    -- (nanosiem.ioc_enrichment_dict keyed on the raw entity String;
    --  nanosiem.custom_enrichment_dict keyed on tuple('ip', <ip>) returning
    --  Array(String) tags joined with ', '). Parity with clickhouse/init.sql
    --  ioc_*_threat_type / custom_*_ip_tags. Enriches nano-OWNED OCSF ingestion.
    `enrichments.ioc_src_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_dest_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_domain_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_hash_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_src_ip_tags` String CODEC(ZSTD(1)),
    `enrichments.custom_dest_ip_tags` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- METADATA / PROVENANCE  (standard OCSF `metadata` object — source identity)
    -- =========================================================================
    -- Core OCSF provenance promoted out of the `event` tail (NAN-1241). These are
    -- scalar string_t attributes of the standard `metadata` object (and its nested
    -- `product` / `product.feature` objects), verified against OCSF 1.8.0
    -- objects/metadata + objects/product + objects/feature. Rare/array/time
    -- metadata attributes (profiles, labels, tenant_uid, logged_time, ...) stay in
    -- the tail. Case is PRESERVED (these are display labels / opaque ids, not
    -- host/user/ip — so NOT lower()'d, unlike the network/identity columns).
    --
    -- metadata.product.name == THE OCSF SOURCE IDENTIFIER (the source_type analog).
    -- The reporting product (e.g. 'apache http server'). This is the per-source
    -- axis the UI's source selector should read for OCSF rows — DISTINCT from
    -- class_uid (the event CLASS). bloom_filter + PREWHERE-eligible. UDM vendor_product.
    `metadata.product.name` String CODEC(ZSTD(1)),
    -- metadata.product.vendor_name — vendor of the reporting product. Low-card.
    `metadata.product.vendor_name` LowCardinality(String) CODEC(ZSTD(1)),
    -- metadata.product.feature.name — feature / log-type sub-source (feature object
    -- nested under product). Finer-grained than product.name. bloom.
    `metadata.product.feature.name` String CODEC(ZSTD(1)),
    -- metadata.log_name — log channel / source file (e.g. access.log, 'Security'). bloom.
    `metadata.log_name` String CODEC(ZSTD(1)),
    -- metadata.log_provider — logging provider / collector (e.g. 'Vector'). Low-card.
    `metadata.log_provider` LowCardinality(String) CODEC(ZSTD(1)),
    -- metadata.uid — producer-assigned unique event id (UDM id/event_id; opaque
    -- String, NOT a CH UUID). bloom for by-id lookup/dedup pivots.
    `metadata.uid` String CODEC(ZSTD(1)),
    -- metadata.version — OCSF schema version of the record (e.g. '1.8.0'). Low-card.
    `metadata.version` LowCardinality(String) CODEC(ZSTD(1)),
    -- metadata.correlation_uid — producer correlation id grouping related events. bloom.
    `metadata.correlation_uid` String CODEC(ZSTD(1)),

    -- =========================================================================
    -- PREVALENCE  (asset-card parity with UDM logs.prevalence_* — NAN-1248)
    -- =========================================================================
    -- Ingest-time host_count lookups against the SCHEMA-AGNOSTIC prevalence dicts
    -- (nanosiem.{hash,domain,ip}_prevalence_dict). These dicts are shared with UDM
    -- `logs` — same names, same layout — so OCSF rows feed and read the exact same
    -- prevalence universe. Mirror clickhouse/init.sql lines 738-741 byte-for-byte
    -- (same dictGetOrDefault, same 9999/65535 sentinels) but keyed on the OCSF
    -- promoted columns instead of the UDM ones:
    --   prevalence_file_hash    <- file.hashes.sha256
    --   prevalence_process_hash <- process.file.hashes.sha256  (the SUBJECT process)
    --   prevalence_dest_domain  <- dst_endpoint.hostname
    --   prevalence_dest_ip      <- dst_endpoint.ip
    -- UInt16, NUMERIC (never lower()'d). Hash columns are already lowercased at
    -- ingest (see lower() in the hash materializers) so the dict key matches the
    -- UDM hash dict-key convention without re-lowering here.
    `prevalence_file_hash` UInt16 MATERIALIZED if(`file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_process_hash` UInt16 MATERIALIZED if(`process.file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `process.file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_domain` UInt16 MATERIALIZED if(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(`dst_endpoint.hostname`), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_ip` UInt16 MATERIALIZED if(`dst_endpoint.ip` != '' AND NOT (match(`dst_endpoint.ip`, '^10\\.') OR match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR match(`dst_endpoint.ip`, '^192\\.168\\.') OR match(`dst_endpoint.ip`, '^127\\.') OR match(`dst_endpoint.ip`, '^169\\.254\\.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', `dst_endpoint.ip`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    -- prevalence_min: least() of the four prevalence columns above, mirroring UDM
    -- logs.prevalence_min EXACTLY (NAN-1383). UDM's inline definition contributes
    -- 9999 (not 65535) for an ABSENT entity, so the per-column 65535 "no entity"
    -- sentinel is remapped to 9999 before the least() — an event with no tracked
    -- entities reads 9999 ("common/not-tracked"), never 65535. Unlike UDM (which
    -- had to inline the dict lookups — CH 26.x couldn't resolve inter-column
    -- DEFAULT refs during INSERT), MATERIALIZED→MATERIALIZED references resolve
    -- fine at insert on this table (prevalence_file_hash itself reads the
    -- MATERIALIZED `file.hashes.sha256`), so reference the columns directly.
    `prevalence_min` UInt16 MATERIALIZED least(
        if(prevalence_file_hash = 65535, toUInt16(9999), prevalence_file_hash),
        if(prevalence_process_hash = 65535, toUInt16(9999), prevalence_process_hash),
        if(prevalence_dest_domain = 65535, toUInt16(9999), prevalence_dest_domain),
        if(prevalence_dest_ip = 65535, toUInt16(9999), prevalence_dest_ip)
    ) CODEC(T64, LZ4),

    -- =========================================================================
    -- CLASS-SPLIT UNIFIED COLUMNS  (NAN-1333)
    -- =========================================================================
    -- A handful of UDM process/identity/url/host concepts are SPLIT across two
    -- OCSF columns by event class: the "primary/acting" object sits in the
    -- top-level `process`/`user`/`url`/`src_endpoint` on some classes and in
    -- `actor.process`/`actor.user`/`http_request.url`/`device` on others (see
    -- `class_split_udm_field` in nanosiem-core/src/schema/ocsf.rs — the source of
    -- truth). The codegen historically emitted these as an inline value-pick
    -- `if(primary != <sentinel>, primary, fallback)` in WHERE / GROUP BY /
    -- raw-SQL. That `if(...)` is OPAQUE to every skip index (a function of two
    -- columns, not a plain column reference), so every filter on a split concept
    -- FULL-SCANS — even though both source columns are individually indexed.
    --
    -- Fix: materialize the EXACT same union into one plain column per concept and
    -- give it a text index. The codegen (NAN-1333) now emits this indexed column
    -- instead of the inline `if(...)`, so the words index actually prunes (live
    -- prototype: src_host 640/640 → 294/640 granules, identical match counts).
    --
    -- Each column's TYPE mirrors its PRIMARY source column. Sentinel: numeric → 0,
    -- else ''. These reference the ALREADY-materialized source columns, which
    -- carry their own case-normalization (host/user/sha256 are lower()'d at
    -- ingest; process/path/cmd/url are not) — so NO extra lower() here; the union
    -- inherits each source's normalization, keeping codegen semantics byte-exact.
    -- CODEC mirrors the source columns (ZSTD(1) for String, T64/LZ4 for UInt32).
    `process_name_unified` String MATERIALIZED if(`process.name` != '', `process.name`, `actor.process.name`) CODEC(ZSTD(1)),
    `process_path_unified` String MATERIALIZED if(`process.file.path` != '', `process.file.path`, `actor.process.file.path`) CODEC(ZSTD(1)),
    `command_line_unified` String MATERIALIZED if(`process.cmd_line` != '', `process.cmd_line`, `actor.process.cmd_line`) CODEC(ZSTD(1)),
    `process_id_unified` UInt32 MATERIALIZED if(`process.pid` != 0, `process.pid`, `actor.process.pid`) CODEC(T64, LZ4),
    `process_guid_unified` String MATERIALIZED if(`process.uid` != '', `process.uid`, `actor.process.uid`) CODEC(ZSTD(1)),
    `process_hash_unified` String MATERIALIZED if(`process.file.hashes.sha256` != '', `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`) CODEC(ZSTD(1)),
    `user_unified` String MATERIALIZED if(`user.name` != '', `user.name`, `actor.user.name`) CODEC(ZSTD(1)),
    `url_domain_unified` String MATERIALIZED if(`http_request.url.hostname` != '', `http_request.url.hostname`, `url.hostname`) CODEC(ZSTD(1)),
    `url_unified` String MATERIALIZED if(`http_request.url.url_string` != '', `http_request.url.url_string`, `url.url_string`) CODEC(ZSTD(1)),
    `src_host_unified` LowCardinality(String) MATERIALIZED if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, `device.hostname`) CODEC(ZSTD(1)),

    -- =========================================================================
    -- TELEMETRY  (NAN-1385)
    -- =========================================================================
    -- Stored payload size for the per-source telemetry rollup
    -- (ocsf_logs_per_source_5m_mv below). The UDM lane sums length(message) +
    -- length(metadata); the OCSF analog of "the stored payload" is the `event`
    -- JSON itself. Materialized so the rollup MV reads a plain UInt64 —
    -- granting the INSERT-only nanosiem_ingest user SELECT on `event` (raw log
    -- content) would defeat the NAN-1384 least-privilege contract, and
    -- MATERIALIZED-column expressions are exempt from the MV-push SELECT check.
    `event_bytes` UInt64 CODEC(T64, LZ4),

    -- =========================================================================
    -- FULL-TEXT SEARCH  (NAN-1241)
    -- =========================================================================
    -- There are deliberately NO stored `.search` companion columns. The earlier
    -- design materialized a `lower(<col>)` String column per field AND attached
    -- the text index to that column — but the query generator emits the search
    -- predicate as the *expression* `lower(<col>)` (search_expr.rs), never as the
    -- `.search` column name. ClickHouse matches a skip index by EXPRESSION, so a
    -- text index on a stored `.search` column was never used by the real query
    -- path (verified: index-on-column → 0 granules pruned, full scan;
    -- index-on-expression → pruned 24x). Those columns were therefore pure storage
    -- waste (message.search alone ≈ the size of message), AND full-text silently
    -- ran as a full scan.
    --
    -- Fix: the text indexes below are defined on the SAME expression the generator
    -- emits, so they actually prune, and the duplicate `lower()` columns are gone.
    -- The generator emits `lower(<col>)` for full-text on any plain String column
    -- — including `message` — and only wraps ext/JSON/numeric fields in toString
    -- (NAN-1247). So every text index here is `lower(<col>)`; the expressions must
    -- mirror the generator EXACTLY or the index goes dead again.

    -- =========================================================================
    -- SKIP INDEXES  (mirror init.sql's hot-column index strategy)
    -- =========================================================================
    -- Taxonomy ints: bloom_filter for selective equality (manifest index=tokenbf
    -- on numeric taxonomy maps to bloom_filter here, as numbers tokenize trivially
    -- and bloom is the integer-equality pruner used across init.sql).
    INDEX idx_class_uid class_uid TYPE bloom_filter GRANULARITY 4,
    INDEX idx_category_uid category_uid TYPE bloom_filter GRANULARITY 4,
    INDEX idx_activity_id activity_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_type_uid type_uid TYPE bloom_filter GRANULARITY 4,
    INDEX idx_severity_id severity_id TYPE set(20) GRANULARITY 4,
    INDEX idx_severity severity TYPE set(20) GRANULARITY 4,
    INDEX idx_status_id status_id TYPE set(100) GRANULARITY 4,
    INDEX idx_status status TYPE set(100) GRANULARITY 4,
    INDEX idx_auth_protocol_id auth_protocol_id TYPE bloom_filter GRANULARITY 4,
    -- Network entity bloom (parity with UDM src_ip/dest_ip).
    INDEX idx_src_endpoint_ip `src_endpoint.ip` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst_endpoint_ip `dst_endpoint.ip` TYPE bloom_filter GRANULARITY 4,
    -- MAC bloom (parity with UDM src_mac/dest_mac).
    INDEX idx_src_endpoint_mac `src_endpoint.mac` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst_endpoint_mac `dst_endpoint.mac` TYPE bloom_filter GRANULARITY 4,
    -- Host bloom + tokenized text (parity with UDM src_host/dest_host).
    INDEX idx_src_endpoint_hostname `src_endpoint.hostname` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_src_endpoint_hostname_words lower(`src_endpoint.hostname`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_device_hostname `device.hostname` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst_endpoint_hostname `dst_endpoint.hostname` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst_endpoint_hostname_words lower(`dst_endpoint.hostname`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Identity bloom + tokenized text (parity with UDM user/src_user).
    INDEX idx_user_name `user.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user_name_words lower(`user.name`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_user_name `actor.user.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_user_name_words lower(`actor.user.name`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_user_uid `user.uid` TYPE bloom_filter GRANULARITY 4,
    -- Process bloom + tokenized text. SUBJECT (process.*) carries the PRIMARY UDM
    -- process_name/command_line/process_guid/process_hash; PARENT (actor.process.*)
    -- carries parent_command_line + parent pivots.
    INDEX idx_process_name `process.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_name_words lower(`process.name`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_process_name `actor.process.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_process_name_words lower(`actor.process.name`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- cmd_line: manifest index=tokenbf -> tokenized text index on lower() (UDM
    -- command_line full-text hunt parity, e.g. 'System32'). process.cmd_line is the
    -- subject (UDM command_line); actor.process.cmd_line is the parent (UDM
    -- parent_command_line).
    INDEX idx_process_cmd_line_words lower(`process.cmd_line`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_process_cmd_line_words lower(`actor.process.cmd_line`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Process image paths tokenized text (UDM process_path/parent_process_path
    -- path-fragment hunt parity; subject == UDM process_path, actor == parent).
    INDEX idx_process_file_path_words lower(`process.file.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_process_file_path_words lower(`actor.process.file.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Process uid bloom (subject == UDM process_guid; actor == parent pivot).
    INDEX idx_process_uid `process.uid` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_process_uid `actor.process.uid` TYPE bloom_filter GRANULARITY 4,
    -- Process hashes bloom (subject == UDM process_hash; actor == parent hash).
    INDEX idx_process_file_sha256 `process.file.hashes.sha256` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_process_file_sha256 `actor.process.file.hashes.sha256` TYPE bloom_filter GRANULARITY 4,
    -- File: name bloom; path tokenized text (UDM file_name/file_path parity).
    INDEX idx_file_name `file.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_file_path_words lower(`file.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_file_sha256 `file.hashes.sha256` TYPE bloom_filter GRANULARITY 4,
    -- Module (Module Activity 1005): image path tokenized text; file name bloom.
    INDEX idx_module_file_path_words lower(`module.file.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_module_file_name `module.file.name` TYPE bloom_filter GRANULARITY 4,
    -- Web (Network Activity 4001 top-level url): url_hostname bloom (domain
    -- entity); url_string tokenized text.
    INDEX idx_url_hostname `url.hostname` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_url_string_words lower(`url.url_string`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- HTTP (4002): method set; the HTTP URL lives under http_request.url —
    -- hostname bloom (UDM url_domain for HTTP, domain entity), url_string +
    -- path + user_agent tokenized text (UDM url / http_* parity).
    INDEX idx_http_method `http_request.http_method` TYPE set(20) GRANULARITY 4,
    INDEX idx_http_url_hostname `http_request.url.hostname` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_http_url_string_words lower(`http_request.url.url_string`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_http_url_path_words lower(`http_request.url.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_http_user_agent_words lower(`http_request.user_agent`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- NAN-1465 promotions: lower(col) forms so the lower()-based codegen hits them.
    INDEX idx_reg_key_path_words lower(`reg_key.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_reg_value_path_words lower(`reg_value.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_reg_value_name lower(`reg_value.name`) TYPE bloom_filter GRANULARITY 4,
    INDEX idx_reg_value_data_words lower(`reg_value.data`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_http_referrer_words lower(`http_request.referrer`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_user_uid lower(`actor.user.uid`) TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_user_type lower(`actor.user.type`) TYPE set(20) GRANULARITY 4,
    -- DNS: query tokenized text (UDM query parity); answer rdata bloom (UDM answer).
    INDEX idx_query_words lower(`query.hostname`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_answer `answers.rdata` TYPE bloom_filter GRANULARITY 4,
    -- Email: sender/recipient/message_id bloom; subject tokenized text.
    INDEX idx_email_from `email.from` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_email_to `email.to` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_email_subject_words lower(`email.subject`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_email_message_uid `email.message_uid` TYPE bloom_filter GRANULARITY 4,
    -- Finding: cve bloom (UDM cve).
    INDEX idx_cve `vulnerabilities.cve.uid` TYPE bloom_filter GRANULARITY 4,
    -- Cloud: provider/region/account_name set; account_id bloom (UDM cloud_* parity).
    INDEX idx_cloud_provider `cloud.provider` TYPE set(20) GRANULARITY 4,
    INDEX idx_cloud_account_id `cloud.account.uid` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_cloud_account_name `cloud.account.name` TYPE set(500) GRANULARITY 4,
    INDEX idx_cloud_region `cloud.region` TYPE set(100) GRANULARITY 4,
    -- Cloud API Activity (6003): service.name + resource_type set; resource uid/name
    -- bloom (UDM cloud_service / resource_* pivots). change_type reuses idx_activity_id.
    INDEX idx_api_service_name `api.service.name` TYPE set(100) GRANULARITY 4,
    INDEX idx_api_operation `api.operation` TYPE set(100) GRANULARITY 4,
    INDEX idx_resources_type `resources.type` TYPE set(200) GRANULARITY 4,
    INDEX idx_resources_uid `resources.uid` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_resources_name `resources.name` TYPE bloom_filter GRANULARITY 4,
    -- Enrichment geo/asn (DUAL-MODE; parity with UDM enriched_* indexes).
    INDEX idx_enriched_src_country `src_endpoint.location.country` TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_src_continent `src_endpoint.location.continent` TYPE set(10) GRANULARITY 4,
    INDEX idx_enriched_src_asn `src_endpoint.autonomous_system.number` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_src_as_name `src_endpoint.autonomous_system.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_dest_country `dst_endpoint.location.country` TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_dest_continent `dst_endpoint.location.continent` TYPE set(10) GRANULARITY 4,
    INDEX idx_enriched_dest_asn `dst_endpoint.autonomous_system.number` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_dest_as_name `dst_endpoint.autonomous_system.name` TYPE bloom_filter GRANULARITY 4,
    -- Enrichment IOC/custom (DUAL-MODE; parity with UDM ioc_*/enrichment_value_* bloom).
    INDEX idx_ioc_src_ip `enrichments.ioc_src_ip_threat_type` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ioc_dest_ip `enrichments.ioc_dest_ip_threat_type` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ioc_domain `enrichments.ioc_domain_threat_type` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ioc_hash `enrichments.ioc_hash_threat_type` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_custom_src_ip `enrichments.custom_src_ip_tags` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_custom_dest_ip `enrichments.custom_dest_ip_tags` TYPE bloom_filter GRANULARITY 4,
    -- Metadata / provenance: product.name is the source identifier (bloom + PREWHERE);
    -- vendor_name/log_provider/version are low-card set; feature/log_name/uid/correlation bloom.
    INDEX idx_metadata_product_name `metadata.product.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_metadata_vendor_name `metadata.product.vendor_name` TYPE set(200) GRANULARITY 4,
    INDEX idx_metadata_feature_name `metadata.product.feature.name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_metadata_log_name `metadata.log_name` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_metadata_log_provider `metadata.log_provider` TYPE set(100) GRANULARITY 4,
    INDEX idx_metadata_uid `metadata.uid` TYPE bloom_filter GRANULARITY 4,
    INDEX idx_metadata_version `metadata.version` TYPE set(20) GRANULARITY 4,
    INDEX idx_metadata_correlation_uid `metadata.correlation_uid` TYPE bloom_filter GRANULARITY 4,
    -- Message: tokenized text (UDM message parity — primary full-text hunt).
    INDEX idx_message_words lower(message) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Operational provenance key set index (byte-for-byte parity with UDM
    -- logs.idx_source_type — the high-frequency first-filter fast-path).
    INDEX idx_source_type source_type TYPE set(100) GRANULARITY 4,
    -- Insert clock minmax (parity with UDM idx_inserted_at).
    INDEX idx_inserted_at _inserted_at TYPE minmax GRANULARITY 4,
    -- =========================================================================
    -- CLASS-SPLIT UNIFIED text indexes  (NAN-1333)
    -- =========================================================================
    -- One words text index per unified column. The codegen routes WHERE / GROUP
    -- BY / raw-SQL for the split concepts to the plain `<col>_unified` reference,
    -- so an index on `lower(<col>_unified)` is matched by EXPRESSION exactly like
    -- the per-source `*_words` indexes above (the prototype showed the words index
    -- is the workhorse; a bloom barely helped, so words-index only).
    INDEX idx_process_name_unified_words lower(process_name_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_path_unified_words lower(process_path_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_command_line_unified_words lower(command_line_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- process_id_unified is NUMERIC (UInt32): a `lower()` text index is illegal on
    -- an integer (CH ILLEGAL_TYPE_OF_ARGUMENT), and the codegen emits an integer
    -- equality for `process_id=N` — not a tokenized text match. Use bloom_filter,
    -- the integer-equality pruner used across this schema (idx_class_uid etc.).
    INDEX idx_process_id_unified process_id_unified TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_guid_unified_words lower(process_guid_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_hash_unified_words lower(process_hash_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_user_unified_words lower(user_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_domain_unified_words lower(url_domain_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_unified_words lower(url_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_src_host_unified_words lower(src_host_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Prevalence range-hunt minmax (NAN-1691; parity with UDM logs.prevalence_*).
    INDEX idx_prevalence_file_hash prevalence_file_hash TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_process_hash prevalence_process_hash TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_dest_domain prevalence_dest_domain TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_dest_ip prevalence_dest_ip TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_min prevalence_min TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree
-- Daily partitions for partition pruning on time-range queries (UDM parity).
PARTITION BY toYYYYMMDD(timestamp)
-- -----------------------------------------------------------------------------
-- SORT-KEY DECISION  (NAN-1334 — UDM-shaped key for hot-entity bloom selectivity)
-- -----------------------------------------------------------------------------
-- UDM orders by (source_type, timestamp, src_host, src_ip, cityHash64(id)) and
-- we now adopt the UDM-shaped key here:
--     ORDER BY (class_uid, timestamp, `src_endpoint.ip`, cityHash64(id))
--
-- THE MECHANISM — clustering for bloom selectivity. A bloom skip index only
-- prunes granules where the wanted value is ABSENT. Under the old time-only key
-- `(timestamp, cityHash64(id))` a given src IP is scattered randomly w.r.t. the
-- sort order, so every granule contains a few rows for any busy IP and the
-- `idx_src_endpoint_ip` bloom can prune NOTHING — a hot-entity point lookup
-- (`src_endpoint.ip = '<busy server>'`) degrades to a full scan. Putting the IP
-- IN the sort key physically CLUSTERS each IP's rows into a handful of adjacent
-- granules, so the same bloom now prunes the rest. The entity column need not
-- LEAD the key for this to work — in UDM `src_ip` is the 4th key column and the
-- clustering still holds; here `src_endpoint.ip` is likewise 3rd.
--
-- PROVEN (controlled A/B on live local CH, identical data + identical bloom):
-- adding `src_endpoint.ip` to the sort key took the hot IP `198.51.100.25` from
-- 146/146 granules / 1,190,097 rows_read  →  26/145 granules / 216,966 rows_read
-- (~5.5x less I/O) with the SAME 7,345 matches.
--
-- WHY LEAD WITH `class_uid`. It is the OCSF analog of UDM `source_type` — the
-- per-source event-kind discriminator and the highest-selectivity first filter a
-- SIEM hunt typically pins (`class_uid = 1007`, the OCSF `source_type=...`
-- analog). Leading with it mirrors UDM byte-for-byte and lets the bloom/PREWHERE
-- fast-path prune on the event kind before time.
--
-- WHY THESE COLUMNS ARE DEFAULT, NOT MATERIALIZED. ClickHouse forbids
-- MATERIALIZED columns in the sort key (§2.4) — the exact constraint that already
-- forced `timestamp` to be a client-written DEFAULT column. NAN-1334 extends that
-- same carve-out to `class_uid` and `src_endpoint.ip`: both are flipped
-- MATERIALIZED -> DEFAULT (identical expression / type / CODEC), which is
-- sort-key-legal while still deriving from `event` on insert.
--
-- TRADEOFFS (accepted, honest):
--   * DEFAULT (unlike MATERIALIZED) lets a client WRITE `class_uid` /
--     `src_endpoint.ip` and surfaces them in SELECT *; a client-supplied value is
--     used AS-IS and CAN diverge from `event`. This is the identical tradeoff
--     already accepted for `timestamp`.
--   * Leading with `class_uid` slightly deprioritizes pure filter-less
--     time-range scans (no class pinned) vs a time-led key — the deliberate UDM
--     bet that real hunts pin a discriminator, and partition pruning still bounds
--     the time range.
--
-- Tiebreaker is `cityHash64(id)` — `id` is the server-owned non-materialized row
-- key (UUIDv7 DEFAULT, NAN-1241). It REPLACES the earlier `cityHash64(toString(event))`,
-- which serialized the ENTIRE JSON record to a string per row: measured ~3000x more
-- expensive on local CH (19.6s vs 6.6ms / 1M rows for the hash alone) — a cost paid
-- at every background merge and every SAMPLE BY query. `id` is unique, well-distributed
-- and 16 bytes: the cheap, correct tiebreaker the original comment said it lacked.
ORDER BY (class_uid, timestamp, `src_endpoint.ip`, cityHash64(id))
SAMPLE BY cityHash64(id)
-- 365-day TTL (parity with UDM logs).
-- NAN-1384 (G17) GUARD: only rows with a sane (post-2000) timestamp are subject
-- to retention expiry. Without the WHERE, a row whose timestamp landed at 1970
-- (e.g. a client explicitly writing a bad `timestamp`) was deleted at part-write
-- while the INSERT returned HTTP 200 — silent annihilation with no dead-letter.
-- Garbage-timestamped rows now survive (visible, debuggable) instead of
-- vanishing; normal rows expire exactly as before.
TTL timestamp + toIntervalDay(365) DELETE WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC')
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (nanosiem.ocsf_logs_raw_mv — Null -> MergeTree)
-- =============================================================================
-- NAN-1443: reads each block inserted into nanosiem.ocsf_logs_raw, derives every
-- promoted column from `event` (the EXACT expressions that were MATERIALIZED /
-- DEFAULT on the old single-table ocsf_logs), and writes the result to
-- nanosiem.ocsf_logs. This pattern works for BOTH implicit (Vector clickhouse
-- sink — no column list) and explicit (Tenzir — `(event, source_type)`) inserts,
-- because `event` is a normal (non-ephemeral) column on the staging table.
-- The `*_unified` columns are NOT selected here (they MATERIALIZE on ocsf_logs
-- from these plain columns); `_inserted_at` (DEFAULT now64 on ocsf_logs) and
-- `time_dt` (ALIAS) are likewise omitted. The `prevalence_*` columns are also
-- MATERIALIZED on ocsf_logs (from the plain hash/ip/domain columns), so they are
-- not selected here either.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv
TO nanosiem.ocsf_logs
AS SELECT
    timestamp,
    source_type,
    id,
    JSONExtractUInt(event, 'class_uid') AS `class_uid`,
    JSONExtractUInt(event, 'category_uid') AS `category_uid`,
    JSONExtractUInt(event, 'activity_id') AS `activity_id`,
    JSONExtractString(event, 'activity_name') AS `activity`,
    JSONExtractUInt(event, 'type_uid') AS `type_uid`,
    JSONExtractUInt(event, 'severity_id') AS `severity_id`,
    JSONExtractString(event, 'severity') AS `severity`,
    JSONExtractUInt(event, 'status_id') AS `status_id`,
    JSONExtractString(event, 'status') AS `status`,
    JSONExtractString(event, 'message') AS `message`,
    event.^unmapped AS `unmapped`,
    lower(JSONExtractString(event, 'src_endpoint', 'ip')) AS `src_endpoint.ip`,
    lower(JSONExtractString(event, 'dst_endpoint', 'ip')) AS `dst_endpoint.ip`,
    toUInt16(JSONExtractUInt(event, 'src_endpoint', 'port')) AS `src_endpoint.port`,
    toUInt16(JSONExtractUInt(event, 'dst_endpoint', 'port')) AS `dst_endpoint.port`,
    lower(JSONExtractString(event, 'src_endpoint', 'mac')) AS `src_endpoint.mac`,
    lower(JSONExtractString(event, 'dst_endpoint', 'mac')) AS `dst_endpoint.mac`,
    lower(JSONExtractString(event, 'src_endpoint', 'hostname')) AS `src_endpoint.hostname`,
    lower(JSONExtractString(event, 'device', 'hostname')) AS `device.hostname`,
    lower(JSONExtractString(event, 'dst_endpoint', 'hostname')) AS `dst_endpoint.hostname`,
    JSONExtractInt(event, 'connection_info', 'protocol_num') AS `connection_info.protocol_num`,
    JSONExtractUInt(event, 'traffic', 'bytes_in') AS `traffic.bytes_in`,
    JSONExtractUInt(event, 'traffic', 'bytes_out') AS `traffic.bytes_out`,
    JSONExtractUInt(event, 'traffic', 'packets_in') AS `traffic.packets_in`,
    JSONExtractUInt(event, 'traffic', 'packets_out') AS `traffic.packets_out`,
    lower(JSONExtractString(event, 'user', 'name')) AS `user.name`,
    lower(JSONExtractString(event, 'actor', 'user', 'name')) AS `actor.user.name`,
    lower(JSONExtractString(event, 'user', 'domain')) AS `user.domain`,
    JSONExtractString(event, 'user', 'uid') AS `user.uid`,
    JSONExtractString(event, 'process', 'name') AS `process.name`,
    JSONExtractString(event, 'process', 'cmd_line') AS `process.cmd_line`,
    JSONExtractUInt(event, 'process', 'pid') AS `process.pid`,
    JSONExtractString(event, 'process', 'uid') AS `process.uid`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'process', 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `process.file.hashes.sha256`,
    JSONExtractString(event, 'process', 'file', 'path') AS `process.file.path`,
    JSONExtractString(event, 'actor', 'process', 'name') AS `actor.process.name`,
    JSONExtractString(event, 'actor', 'process', 'cmd_line') AS `actor.process.cmd_line`,
    JSONExtractUInt(event, 'actor', 'process', 'pid') AS `actor.process.pid`,
    JSONExtractString(event, 'actor', 'process', 'uid') AS `actor.process.uid`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'actor', 'process', 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `actor.process.file.hashes.sha256`,
    JSONExtractString(event, 'actor', 'process', 'file', 'path') AS `actor.process.file.path`,
    JSONExtractString(event, 'file', 'name') AS `file.name`,
    JSONExtractString(event, 'file', 'path') AS `file.path`,
    JSONExtractString(event, 'module', 'file', 'path') AS `module.file.path`,
    JSONExtractString(event, 'module', 'file', 'name') AS `module.file.name`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `file.hashes.sha256`,
    JSONExtractUInt(event, 'auth_protocol_id') AS `auth_protocol_id`,
    JSONExtractString(event, 'auth_protocol') AS `auth_protocol`,
    JSONExtractString(event, 'session', 'uid') AS `session.uid`,
    toUInt8(JSONExtractBool(event, 'is_mfa')) AS `is_mfa`,
    JSONExtractString(event, 'url', 'hostname') AS `url.hostname`,
    JSONExtractString(event, 'url', 'url_string') AS `url.url_string`,
    JSONExtractString(event, 'http_request', 'http_method') AS `http_request.http_method`,
    JSONExtractString(event, 'http_request', 'url', 'hostname') AS `http_request.url.hostname`,
    JSONExtractString(event, 'http_request', 'url', 'url_string') AS `http_request.url.url_string`,
    JSONExtractString(event, 'http_request', 'url', 'path') AS `http_request.url.path`,
    JSONExtractString(event, 'http_request', 'user_agent') AS `http_request.user_agent`,
    toUInt16(JSONExtractUInt(event, 'http_response', 'code')) AS `http_response.code`,
    -- NAN-1465 promotions
    JSONExtractString(event, 'reg_key', 'path') AS `reg_key.path`,
    JSONExtractString(event, 'reg_value', 'name') AS `reg_value.name`,
    JSONExtractString(event, 'reg_value', 'path') AS `reg_value.path`,
    JSONExtractString(event, 'reg_value', 'data') AS `reg_value.data`,
    JSONExtractString(event, 'http_request', 'referrer') AS `http_request.referrer`,
    JSONExtract(toString(event), 'http_request', 'url', 'categories', 'Array(String)') AS `http_request.url.categories`,
    JSONExtractString(event, 'actor', 'user', 'uid') AS `actor.user.uid`,
    JSONExtractString(event, 'actor', 'user', 'type') AS `actor.user.type`,
    toUInt32(JSONExtractUInt(event, 'duration')) AS `duration`,
    JSONExtractString(event, 'query', 'hostname') AS `query.hostname`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'answers')),
            1
        ),
        'rdata'
    ) AS `answers.rdata`,
    lower(JSONExtractString(event, 'email', 'from')) AS `email.from`,
    lower(
        JSONExtractString(JSONExtractRaw(event, 'email', 'to'), 1)
    ) AS `email.to`,
    JSONExtractString(event, 'email', 'subject') AS `email.subject`,
    JSONExtractString(event, 'email', 'message_uid') AS `email.message_uid`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'vulnerabilities')),
            1
        ),
        'cve', 'uid'
    ) AS `vulnerabilities.cve.uid`,
    JSONExtractString(event, 'cloud', 'provider') AS `cloud.provider`,
    JSONExtractString(event, 'cloud', 'account', 'uid') AS `cloud.account.uid`,
    JSONExtractString(event, 'cloud', 'account', 'name') AS `cloud.account.name`,
    JSONExtractString(event, 'cloud', 'region') AS `cloud.region`,
    JSONExtractString(event, 'api', 'service', 'name') AS `api.service.name`,
    JSONExtractString(event, 'api', 'operation') AS `api.operation`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'type'
    ) AS `resources.type`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'uid'
    ) AS `resources.uid`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'name'
    ) AS `resources.name`,
    if(JSONExtractString(event, 'src_endpoint', 'location', 'country') != '', JSONExtractString(event, 'src_endpoint', 'location', 'country'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.location.country`,
    if(JSONExtractString(event, 'src_endpoint', 'location', 'continent') != '', JSONExtractString(event, 'src_endpoint', 'location', 'continent'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.location.continent`,
    if(JSONExtractUInt(event, 'src_endpoint', 'autonomous_system', 'number') != 0, JSONExtractUInt(event, 'src_endpoint', 'autonomous_system', 'number'), if(`src_endpoint.ip` != '', toUInt32OrZero(replaceRegexpAll(if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(`src_endpoint.ip`), '')), '[^0-9]', '')), 0)) AS `src_endpoint.autonomous_system.number`,
    if(JSONExtractString(event, 'src_endpoint', 'autonomous_system', 'name') != '', JSONExtractString(event, 'src_endpoint', 'autonomous_system', 'name'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.autonomous_system.name`,
    if(JSONExtractString(event, 'dst_endpoint', 'location', 'country') != '', JSONExtractString(event, 'dst_endpoint', 'location', 'country'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.location.country`,
    if(JSONExtractString(event, 'dst_endpoint', 'location', 'continent') != '', JSONExtractString(event, 'dst_endpoint', 'location', 'continent'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.location.continent`,
    if(JSONExtractUInt(event, 'dst_endpoint', 'autonomous_system', 'number') != 0, JSONExtractUInt(event, 'dst_endpoint', 'autonomous_system', 'number'), if(`dst_endpoint.ip` != '', toUInt32OrZero(replaceRegexpAll(if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(`dst_endpoint.ip`), '')), '[^0-9]', '')), 0)) AS `dst_endpoint.autonomous_system.number`,
    if(JSONExtractString(event, 'dst_endpoint', 'autonomous_system', 'name') != '', JSONExtractString(event, 'dst_endpoint', 'autonomous_system', 'name'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.autonomous_system.name`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_src_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_src_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `src_endpoint.ip`, ''), '')) AS `enrichments.ioc_src_ip_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_dest_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_dest_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `dst_endpoint.ip`, ''), '')) AS `enrichments.ioc_dest_ip_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_domain_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_domain_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), multiIf(`url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), ''), `http_request.url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), ''), `query.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), ''), '')) AS `enrichments.ioc_domain_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_hash_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_hash_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), multiIf(`file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), ''), `process.file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), ''), '')) AS `enrichments.ioc_hash_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_src_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_src_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`src_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `src_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_src_ip_tags`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_dest_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_dest_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`dst_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `dst_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_dest_ip_tags`,
    JSONExtractString(event, 'metadata', 'product', 'name') AS `metadata.product.name`,
    JSONExtractString(event, 'metadata', 'product', 'vendor_name') AS `metadata.product.vendor_name`,
    JSONExtractString(event, 'metadata', 'product', 'feature', 'name') AS `metadata.product.feature.name`,
    JSONExtractString(event, 'metadata', 'log_name') AS `metadata.log_name`,
    JSONExtractString(event, 'metadata', 'log_provider') AS `metadata.log_provider`,
    JSONExtractString(event, 'metadata', 'uid') AS `metadata.uid`,
    JSONExtractString(event, 'metadata', 'version') AS `metadata.version`,
    JSONExtractString(event, 'metadata', 'correlation_uid') AS `metadata.correlation_uid`,
    length(toString(event)) AS `event_bytes`
FROM nanosiem.ocsf_logs_raw
;

-- =============================================================================
-- NATIVE-ENTRYPOINT FORWARDER  (nanosiem.ocsf_logs_native_raw_mv)
-- =============================================================================
-- NAN-1603: forwards native-protocol inserts (Tenzir `to_clickhouse`, port 9000)
-- from the type-restricted ocsf_logs_native_raw entrypoint into ocsf_logs_raw,
-- where the timestamp/id DEFAULTs fill in and ocsf_logs_raw_mv performs every
-- promotion. NO projection is duplicated here — ocsf_logs_raw_mv stays the single
-- source of truth for derivation. ClickHouse cascades the chain:
--   ocsf_logs_native_raw -> (this MV) -> ocsf_logs_raw -> ocsf_logs_raw_mv -> ocsf_logs.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_native_raw_mv
TO nanosiem.ocsf_logs_raw
AS SELECT
    event,
    source_type
FROM nanosiem.ocsf_logs_native_raw
;

-- =============================================================================
-- PREVALENCE INFRASTRUCTURE  (NAN-1248 — asset-card parity)
-- =============================================================================
-- The prevalence summary tables and dicts are SCHEMA-AGNOSTIC: they key on the
-- artifact (hash / domain / ip) regardless of which landing table produced the
-- row. UDM `clickhouse/init.sql` already CREATEs them when nano owns the UDM
-- table; this OCSF bootstrap re-declares them IF NOT EXISTS / CREATE OR REPLACE
-- (idempotent — identical names, columns, layout) so an OCSF-only deployment
-- still has a working prevalence universe. The defs below are copied verbatim
-- from clickhouse/init.sql + clickhouse/110_prevalence_summary_tables.sql; the
-- only OCSF-specific additions are the *_prevalence_summary_mv views at the
-- bottom, which read FROM nanosiem.ocsf_logs and feed the SAME summary tables.
--
-- The prevalence_* MATERIALIZED columns above read these dicts at insert time.
-- ClickHouse resolves dictGetOrDefault lazily, so the columns work once the
-- dicts exist (created here) and accrue counts as the summary MVs populate.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Summary tables (entity-keyed; AggregatingMergeTree). Copied from
-- clickhouse/init.sql / 110_prevalence_summary_tables.sql verbatim.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_summary
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (file_hash, hash_type)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (domain, is_subdomain)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_summary
(
    `ip` String,
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (ip, is_private)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

-- -----------------------------------------------------------------------------
-- Prevalence dictionaries. Copied from clickhouse/init.sql (FRO-243 /
-- NAN-606 / NAN-706 layout). These CACHE dicts deliberately keep
-- KEY-PUSHDOWN sources — they are NOT staged (NAN-1440 reverted NAN-1407's
-- staging for this family): CACHE layouts push the missed keys into the
-- source QUERY, so each miss runs a small, memory-bounded (512 MiB cap,
-- 256 MiB spill, 2 threads — migrations 112/130) aggregation over a handful
-- of keys, while the staging model full-rewrote the entire aggregated
-- keyspace every 10 minutes (83.39M rows / ~1.6 GiB per cycle measured on
-- Saturn — and its seed OOMed the boot-gating migrator at the 512 MiB
-- bound). Rule: full-reload dicts (HASHED/IP_TRIE) get staging indirection;
-- CACHE dicts keep pushdown. HOST/PORT/USER/PASSWORD use the
-- runner-substituted {clickhouse_self_*} placeholders, same as UDM init.sql
-- (never hardcode creds in a numbered/bootstrap file).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict
(
    file_hash String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY file_hash
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT file_hash,
                  if(uniqMerge(host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.hash_prevalence_summary
           GROUP BY file_hash
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

CREATE OR REPLACE DICTIONARY nanosiem.domain_prevalence_dict
(
    domain String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY domain
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT domain,
                  if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.domain_prevalence_summary
           GROUP BY domain
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

CREATE OR REPLACE DICTIONARY nanosiem.ip_prevalence_dict
(
    ip String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT ip,
                  if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.ip_prevalence_summary
           WHERE is_private = 0
           GROUP BY ip
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));

-- -----------------------------------------------------------------------------
-- Prevalence aggregation tables + chained summary MVs (agg -> summary).
-- Re-declared verbatim from clickhouse/init.sql (NAN-365 layout) so this OCSF
-- bootstrap is SELF-SUFFICIENT for the agg-routed prevalence chain regardless of
-- whether clickhouse/init.sql has run first: the OCSF branch MVs below write
-- into these *_prevalence_agg tables, and the chained *_prevalence_summary_mv
-- views fan the agg states into the entity-keyed *_prevalence_summary tables
-- (the dict source). All IF NOT EXISTS with identical names/columns/layout, so
-- a no-op when clickhouse/init.sql already created them.
-- -----------------------------------------------------------------------------

-- Table: domain_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_parent_domain parent_domain TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (domain, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- Table: hash_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `time_bucket` DateTime,
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (file_hash, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- Table: ip_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` LowCardinality(String),
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (ip, direction, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- Chained summary MVs (agg -> summary, pass-through — AggregatingMergeTree
-- background-merges the uniq states). Verbatim from clickhouse/init.sql.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_summary_mv
TO nanosiem.hash_prevalence_summary AS
SELECT
    file_hash,
    hash_type,
    host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.hash_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_summary_mv
TO nanosiem.domain_prevalence_summary AS
SELECT
    domain,
    is_subdomain,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.domain_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_summary_mv
TO nanosiem.ip_prevalence_summary AS
SELECT
    ip,
    is_private,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.ip_prevalence_agg;

-- -----------------------------------------------------------------------------
-- OCSF prevalence branch MVs (NAN-1661 — agg-layer bypass fix). Earlier
-- revisions wrote these DIRECTLY into the entity-keyed *_prevalence_summary
-- tables, BYPASSING *_prevalence_agg. Every explorer / rare / new / export /
-- single / bulk / daily-heatmap / scatter surface reads *_prevalence_agg, so on
-- OCSF-profile tenants all of them returned "never seen" even though the
-- summary-sourced dicts worked (which masked the bug). These now write into the
-- *_prevalence_agg tables EXACTLY like the UDM per-branch MVs (init.sql /
-- 129_prevalence_mv_split.sql), and the chained *_prevalence_summary_mv views
-- above fan them into the summary tables via MV chaining — so ONE write path
-- feeds BOTH the agg-reading surfaces AND the summary-sourced dicts.
-- Bodies mirror the UDM per-branch prevalence MVs; only the source columns
-- differ (OCSF nested names). The host-identity expression mirrors UDM
-- (src_host else src_ip else 'unknown'); OCSF's equivalents are
-- src_endpoint.hostname / src_endpoint.ip. MV NAMES ARE UNCHANGED (they retain
-- the historical *_prevalence_summary_* names) so
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs keeps pinning them.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): ClickHouse checks the INSERTING
-- user's column-level SELECT on nanosiem.ocsf_logs for every column these MVs
-- read while pushing. The INSERT-only `nanosiem_ingest` user (users.d /
-- deploy templates) is granted SELECT on exactly the columns below. If you add
-- an MV over ocsf_logs or widen one's SELECT list, extend that grant in
-- clickhouse/users.d/nanosiem-users.xml + deploy/k8s/clickhouse/clickhouse.yaml
-- + deploy/k8s/{rackspace,aws}-db/clickhouse.yaml.tpl, or direct-writer inserts
-- start failing with ACCESS_DENIED (loud, but an outage).
-- -----------------------------------------------------------------------------

-- ONE MV PER ENTITY BRANCH, never a UNION ALL body: ClickHouse only attaches
-- the insert trigger to the FIRST SELECT of a UNION ALL (NAN-1393; same
-- mechanism as NAN-1386). Branch bodies (validity/TLD filters, cross-branch
-- dedup) mirror the UDM per-branch prevalence MVs in init.sql. Keep in
-- lockstep with clickhouse/129_prevalence_mv_split.sql —
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs enforces equivalence.

-- Hash prevalence (file + process hashes), OCSF columns -> hash_prevalence_summary.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv
TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`file.hashes.sha256`) AS file_hash,
    multiIf(length(`file.hashes.sha256`) = 32, 'md5', length(`file.hashes.sha256`) = 40, 'sha1', length(`file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`file.hashes.sha256` != '') AND ((length(`file.hashes.sha256`) = 32) OR (length(`file.hashes.sha256`) = 40) OR (length(`file.hashes.sha256`) = 64)) AND match(`file.hashes.sha256`, '^[a-fA-F0-9]+$')
GROUP BY file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv
TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`process.file.hashes.sha256`) = 32, 'md5', length(`process.file.hashes.sha256`) = 40, 'sha1', length(`process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`process.file.hashes.sha256` != '') AND ((length(`process.file.hashes.sha256`) = 32) OR (length(`process.file.hashes.sha256`) = 40) OR (length(`process.file.hashes.sha256`) = 64)) AND match(`process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (lower(`file.hashes.sha256`) != lower(`process.file.hashes.sha256`)))
GROUP BY file_hash, hash_type, time_bucket;

-- Domain prevalence (dst_endpoint.hostname / query.hostname / url.hostname),
-- OCSF columns -> domain_prevalence_summary. Validity/TLD filters mirror UDM.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`dst_endpoint.hostname`) AS domain,
    if(length(splitByChar('.', `dst_endpoint.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`dst_endpoint.hostname` != '') AND (position(`dst_endpoint.hostname`, '.') > 0) AND (NOT match(`dst_endpoint.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`dst_endpoint.hostname`, ':') > 0)) AND match(`dst_endpoint.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `dst_endpoint.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `dst_endpoint.hostname`)[-1], '^[0-9]+$')) AND (length(`dst_endpoint.hostname`) <= 253)
    AND (lower(splitByChar('.', `dst_endpoint.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`query.hostname`) AS domain,
    if(length(splitByChar('.', `query.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`query.hostname` != '') AND (position(`query.hostname`, '.') > 0) AND (NOT match(`query.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`query.hostname`, ':') > 0)) AND match(`query.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `query.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `query.hostname`)[-1], '^[0-9]+$')) AND (length(`query.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`query.hostname`)))
    AND (lower(splitByChar('.', `query.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`url.hostname`) AS domain,
    if(length(splitByChar('.', `url.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`url.hostname` != '') AND (position(`url.hostname`, '.') > 0) AND (NOT match(`url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(`url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `url.hostname`)[-1], '^[0-9]+$')) AND (length(`url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`url.hostname`)))
    AND (lower(splitByChar('.', `url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

-- IP prevalence (dst_endpoint.ip / src_endpoint.ip), OCSF columns ->
-- ip_prevalence_summary. is_private classification mirrors UDM.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `dst_endpoint.ip` AS ip,
    'dest' AS direction,
    if(
        match(`dst_endpoint.ip`, '^10\\.') OR
        match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`dst_endpoint.ip`, '^192\\.168\\.') OR
        match(`dst_endpoint.ip`, '^127\\.') OR
        match(`dst_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.ip` != ''
  AND match(`dst_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`dst_endpoint.ip`, '^127\\.')
  AND NOT match(`dst_endpoint.ip`, '^169\\.254\\.')
GROUP BY ip, direction, is_private, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `src_endpoint.ip` AS ip,
    'src' AS direction,
    if(
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^127\\.') OR
        match(`src_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`, if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
  AND match(`src_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`src_endpoint.ip`, '^127\\.')
  AND NOT match(`src_endpoint.ip`, '^169\\.254\\.')
  AND `src_endpoint.ip` != `dst_endpoint.ip`
GROUP BY ip, direction, is_private, time_bucket;

-- -----------------------------------------------------------------------------
-- OCSF aggregation MVs (NAN-1385, G13). Same write-directly-into-the-shared-
-- target pattern as the prevalence MVs above: entity first/last-seen, identity
-- observations (which chains into nat_detection_mv — MV chaining fires
-- downstream MVs on MV-pushed inserts, so NAT detection needs no OCSF-specific
-- MV), cloud Users activity, and per-source telemetry, so data ingested ONLY
-- into ocsf_logs (the direct-write / no-Vector path) reaches every aggregation
-- surface. One MV per entity branch — NEVER a UNION ALL body: ClickHouse only
-- attaches the insert trigger to the first SELECT (NAN-1386).
--
-- Under the transitional Vector dual-write (Vector writes both `logs` and
-- `ocsf_logs`), Vector-lane events are counted by BOTH MV sets — uniq states
-- merge exactly; sum/count aggregates double only while dual-write is in
-- place, same accepted behavior as the prevalence MVs above.
--
-- The ⚠ INGEST-CREDENTIAL COUPLING warning above applies: every column these
-- MVs read is mirrored into the nanosiem_ingest SELECT grant.
-- Migration 128 mirrors this block for existing deployments.
-- -----------------------------------------------------------------------------

-- Entity first/last-seen (asset views), OCSF columns -> entity_time_range_agg.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_ip_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_ip' AS entity_type,
    `src_endpoint.ip` AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
GROUP BY entity_type, entity_value, time_bucket;

-- src_host_unified (src_endpoint.hostname else device.hostname) is already
-- lower()'d at ingest — no extra lower(), matching the agg's lowercase
-- entity_value convention.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_host_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_host' AS entity_type,
    src_host_unified AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE src_host_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

-- user_unified is already lower()'d at ingest (both user.name and
-- actor.user.name materialize through lower()); the lower() here is defensive
-- and keeps the branch self-evidently aligned with the asset reader, which
-- binds lowercased user identifiers.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_user_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'user' AS entity_type,
    lower(user_unified) AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE user_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

-- Identity observations (resolve_identity / lateral movement / NAT via the
-- chained nat_detection_mv). Filters and derivations mirror
-- identity_observations_mv (clickhouse/init.sql): private src IPs only, junk
-- hostnames excluded. `source` falls back to metadata.product.name — THE OCSF
-- source identifier — for direct writers that omit source_type (which
-- DEFAULTs to 'unknown'). namespace/source_priority take the table defaults.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_identity_observations_mv
TO nanosiem.identity_observations
(
    `observed_at` DateTime64(3, 'UTC'),
    `ip` String,
    `hostname` String,
    `fqdn` String,
    `mac` String,
    `user` String,
    `source` LowCardinality(String),
    `domain` LowCardinality(String),
    `ip_type` LowCardinality(String)
)
AS SELECT
    timestamp AS observed_at,
    `src_endpoint.ip` AS ip,
    if(
        position(src_host_unified, '.') > 0 AND position(src_host_unified, '.corp.') > 0,
        substring(src_host_unified, 1, position(src_host_unified, '.') - 1),
        src_host_unified
    ) AS hostname,
    src_host_unified AS fqdn,
    `src_endpoint.mac` AS mac,
    user_unified AS user,
    if(source_type != '' AND source_type != 'unknown', lower(source_type),
       if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown')) AS source,
    multiIf(
        position(user_unified, '\\') > 0, substring(user_unified, 1, position(user_unified, '\\') - 1),
        position(src_host_unified, '.corp.') > 0, 'corp',
        ''
    ) AS domain,
    multiIf(
        match(`src_endpoint.ip`, '^10\\.'), 'private',
        match(`src_endpoint.ip`, '^192\\.168\\.'), 'private',
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'), 'private',
        match(`src_endpoint.ip`, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'), 'vpn',
        match(`src_endpoint.ip`, '^127\\.'), 'loopback',
        'public'
    ) AS ip_type
FROM nanosiem.ocsf_logs
WHERE
    `src_endpoint.ip` != ''
    AND src_host_unified != ''
    AND (
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    )
    AND `src_endpoint.ip` NOT IN ('127.0.0.1', '::1', '0.0.0.0')
    AND src_host_unified NOT IN ('localhost', '-', 'unknown', '');

-- Cloud Users activity (cloud investigation Users tab). The agg's `user` join
-- key must carry the SAME values the cloud surface's profile-resolved user
-- column (user_unified, lower()'d at ingest) produces, so it is written
-- as-is with no extra transform. fail = OCSF-native
-- status_id 2 (Failure) OR http_response.code >= 400 (HTTP-shaped classes).
-- delete_count mirrors the query layer's lossy change_type mapping
-- (SearchService::change_type_activity_id: delete -> activity_id 4) scoped to
-- API Activity 6003, where the change semantics live; UDM 'permission_change'
-- is unrepresentable in OCSF -> permission_change_count is 0 on this lane.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_cloud_user_activity_mv
TO nanosiem.cloud_user_activity_agg
(
    `user` String,
    `time_bucket` DateTime,
    `event_count` UInt64,
    `fail_count` UInt64,
    `permission_change_count` UInt64,
    `delete_count` UInt64,
    `mfa_count` UInt64,
    `no_mfa_count` UInt64,
    `distinct_services` AggregateFunction(uniq, String),
    `distinct_regions` AggregateFunction(uniq, String),
    `distinct_ips` AggregateFunction(uniq, String)
)
AS SELECT
    user_unified AS user,
    toStartOfHour(timestamp) AS time_bucket,
    count() AS event_count,
    countIf(`http_response.code` >= 400 OR status_id = 2) AS fail_count,
    toUInt64(0) AS permission_change_count,
    countIf(class_uid = 6003 AND activity_id = 4) AS delete_count,
    countIf(is_mfa = 1) AS mfa_count,
    countIf(is_mfa = 0) AS no_mfa_count,
    uniqState(toString(`api.service.name`)) AS distinct_services,
    uniqState(toString(`cloud.region`)) AS distinct_regions,
    uniqState(`src_endpoint.ip`) AS distinct_ips
FROM nanosiem.ocsf_logs
WHERE `cloud.provider` != '' AND user_unified != ''
GROUP BY user, time_bucket;

-- Per-source 5-minute telemetry rollup (source health / EPS / GB-day).
-- Direct writers that omit source_type land as their OCSF source identifier
-- (metadata.product.name) instead of a single opaque 'unknown' bucket. bytes
-- sums the materialized event_bytes (see the TELEMETRY column above).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_per_source_5m_mv
TO nanosiem.logs_per_source_5m
(
    `source_type` LowCardinality(String),
    `bucket_start` DateTime,
    `events` UInt64,
    `bytes` UInt64,
    `last_event_at` DateTime64(6, 'UTC'),
    `first_event_at` DateTime64(6, 'UTC')
)
AS SELECT
    if(source_type != '' AND source_type != 'unknown', lower(source_type),
       if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown')) AS source_type,
    toStartOfFiveMinute(timestamp) AS bucket_start,
    count() AS events,
    sum(event_bytes) AS bytes,
    max(timestamp) AS last_event_at,
    min(timestamp) AS first_event_at
FROM nanosiem.ocsf_logs
GROUP BY source_type, bucket_start;

-- =============================================================================
-- CLASS-SPLIT UNIFIED COLUMNS — EXISTING-TENANT OVERLAY  (NAN-1333)
-- =============================================================================
-- The class-split unified columns + their words text indexes are declared inline
-- in the CREATE TABLE above, so a FRESH `ocsf_logs` gets them automatically. But
-- `CREATE TABLE IF NOT EXISTS` is a no-op against an ALREADY-EXISTING table, so an
-- existing OCSF deployment would never grow the new columns. There is no numbered
-- ALTER-migration mechanism for ocsf_logs (the whole schema lives in this
-- init.sql, which the migrator re-runs whenever its hash changes — same
-- idempotent-overlay model the prevalence section above uses). So bring existing
-- tables forward with idempotent ALTERs here: ADD COLUMN / ADD INDEX IF NOT
-- EXISTS are no-ops once present, and MATERIALIZE backfills the column/index over
-- existing parts (runs as an async mutation; safe to re-issue). New rows
-- materialize the column at insert without any mutation.
--
-- NOTE: these MUST stay byte-identical to the inline CREATE TABLE defs above
-- (same expression, type, CODEC) or a re-applied init.sql diverges fresh-vs-grown
-- tables. Keep the two blocks in lockstep.
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `process_name_unified` String MATERIALIZED if(`process.name` != '', `process.name`, `actor.process.name`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `process_path_unified` String MATERIALIZED if(`process.file.path` != '', `process.file.path`, `actor.process.file.path`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `command_line_unified` String MATERIALIZED if(`process.cmd_line` != '', `process.cmd_line`, `actor.process.cmd_line`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `process_id_unified` UInt32 MATERIALIZED if(`process.pid` != 0, `process.pid`, `actor.process.pid`) CODEC(T64, LZ4);
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `process_guid_unified` String MATERIALIZED if(`process.uid` != '', `process.uid`, `actor.process.uid`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `process_hash_unified` String MATERIALIZED if(`process.file.hashes.sha256` != '', `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `user_unified` String MATERIALIZED if(`user.name` != '', `user.name`, `actor.user.name`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `url_domain_unified` String MATERIALIZED if(`http_request.url.hostname` != '', `http_request.url.hostname`, `url.hostname`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `url_unified` String MATERIALIZED if(`http_request.url.url_string` != '', `http_request.url.url_string`, `url.url_string`) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `src_host_unified` LowCardinality(String) MATERIALIZED if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, `device.hostname`) CODEC(ZSTD(1));
-- NAN-1385: telemetry payload-size column (see the TELEMETRY section above).
-- NAN-1443: now a PLAIN column populated by ocsf_logs_raw_mv (length(toString(event))
-- runs in the MV, not here) — `event` is no longer a column on ocsf_logs, so this
-- ALTER MUST NOT reference it. ADD COLUMN IF NOT EXISTS is a no-op on a fresh table
-- (already declared plain in the CREATE TABLE above); it only brings a pre-NAN-1443
-- grown table forward to the plain definition. No MATERIALIZE COLUMN.
ALTER TABLE nanosiem.ocsf_logs ADD COLUMN IF NOT EXISTS `event_bytes` UInt64 CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `process_name_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `process_path_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `command_line_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `process_id_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `process_guid_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `process_hash_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `user_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `url_domain_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `url_unified`;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE COLUMN `src_host_unified`;

ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_process_name_unified_words lower(process_name_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_process_path_unified_words lower(process_path_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_command_line_unified_words lower(command_line_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
-- process_id_unified is numeric (UInt32) → bloom_filter, not a lower() text index.
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_process_id_unified process_id_unified TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_process_guid_unified_words lower(process_guid_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_process_hash_unified_words lower(process_hash_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_user_unified_words lower(user_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_url_domain_unified_words lower(url_domain_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_url_unified_words lower(url_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs ADD INDEX IF NOT EXISTS idx_src_host_unified_words lower(src_host_unified) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;

ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_process_name_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_process_path_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_command_line_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_process_id_unified;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_process_guid_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_process_hash_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_user_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_url_domain_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_url_unified_words;
ALTER TABLE nanosiem.ocsf_logs MATERIALIZE INDEX idx_src_host_unified_words;
