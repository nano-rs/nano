// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared ClickHouse SQL builder for accumulated (decayed) entity risk (NAN-1803).
//!
//! The decayed accumulated risk score is computed at query time over the
//! append-only findings stream (`logs WHERE source_type = 'findings'`,
//! `risk_entity` / `risk_score` columns) by applying a `multiIf` TTL-decay
//! weight per finding over four age buckets:
//!
//! - 0-24h: `decay_0_24h` (default 1.0)
//! - 1-3d:  `decay_1_3d`  (default 0.7)
//! - 3-5d:  `decay_3_5d`  (default 0.4)
//! - 5-7d:  `decay_5_7d`  (default 0.2)
//! - >7d:   excluded (0.0)
//!
//! Before this module the CTE was copy-synced by comment discipline across
//! four `RiskRepository` readers (entity list, decayed overview, threshold
//! view, per-rule contributions). This is the single source of truth for that
//! SQL — the enterprise repository and (P2, NAN-1798) the nPL `dataset=risk`
//! generator both build from here, so drift is structurally impossible.
//!
//! Semantics deliberately preserved from the pre-extraction inline queries
//! (`nanosiem-enterprise/src/risk/repository.rs`):
//!
//! - `round()` (not truncating `toInt64`) on decayed sums so headline scores
//!   match the per-rule contribution breakdown (NAN-1658 / R3).
//! - Cleared-entity boundary via `arrayElement(?, indexOf(?, entity))`
//!   parallel arrays with a trailing `''`/0 sentinel (R4).
//! - Entity type inferred from the VALUE (ip/email/hostname/user) at read
//!   time — the write-side field-name inference disagrees by design (design
//!   doc §3) — EXCEPT `cloud_account`: since NAN-1806 the finding row carries
//!   the write-side stamp (`risk_entity_type`) and the read side honors it for
//!   that one type, which value inference can never produce.
//! - OCSF profile reads the nano risk fields from the stored `unmapped`
//!   spill; UDM reads the real columns (NAN-1254 / NAN-1443).
//!
//! Decay factors and cleared boundaries are threaded as explicit parameters;
//! the cached config provider is a later phase (NAN-1798 P2).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use super::types::{RiskDecayConfig, RiskTimeWindow};

/// The one entity type the read-side VALUE inference can never produce
/// (account ids are opaque strings), so it is honored from the write-side
/// stamp instead (NAN-1806 / NAN-1798 P4). See [`ENTITY_SELECT_COLS`].
pub const CLOUD_ACCOUNT_ENTITY_TYPE: &str = "cloud_account";

// ---------------------------------------------------------------------------
// SQL fragments
//
// These concatenate into the exact statements the repository inlined before
// the extraction (the entity-list and rule-contribution outputs are
// byte-identical; the threshold and overview outputs differ only in comment
// text — asserted token-identical by the sibling tests). Do not "tidy"
// whitespace: byte-stability is what the equivalence tests pin.
// ---------------------------------------------------------------------------

/// Opens the `signal_scores` CTE. Followed by a per-variant SELECT column
/// list, then [`DECAY_FACTOR_EXPR`], then a findings WHERE fragment.
const CTE_OPEN: &str = r#"
            WITH signal_scores AS (
                SELECT
"#;

/// Per-finding decay weight by age bucket.
/// Binds: `(cutoff_24h_us, decay_0_24h, cutoff_3d_us, decay_1_3d,
/// cutoff_5d_us, decay_3_5d, cutoff_7d_us, decay_5_7d)` — see
/// [`decay_factor_binds`].
const DECAY_FACTOR_EXPR: &str = r#"                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 0-24h: decay_0_24h
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 1-3d:  decay_1_3d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 3-5d:  decay_3_5d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 5-7d:  decay_5_7d
                        0.0                                           -- >7d:   excluded
                    ) as decay_factor
"#;

/// Extra `signal_scores` SELECT columns for the nPL `dataset=risk` base source
/// (NAN-1798 P2): the per-finding `rule_id` (feeds `distinct_rules_24h/7d`) and
/// the finding's MITRE tactic list (feeds `distinct_tactics_24h/7d`). Placed
/// BEFORE [`ENTITY_SELECT_COLS`] so the trailing decay-factor comment stays
/// adjacent to its `multiIf`. Tactics ride the finding `metadata` JSON on UDM
/// (`findings.rs` `to_log_json`) and the stored `unmapped` vendor extension
/// under OCSF (`build_ocsf_finding_event`) — see
/// [`RiskFindingsSource::tactics_col`].
const DATASET_EXTRA_SELECT_COLS: &str = r#"                    __RULE_ID__ as rule_id,
                    __MITRE_TACTICS__ as tactics,
"#;

/// `signal_scores` SELECT columns for the entity-grain score queries.
///
/// Entity type: the write-side stamp (`risk_entity_type`, NAN-1806) is honored
/// FIRST but only for `cloud_account` — the one type the value inference can
/// never produce (account ids are opaque digit strings that read back as
/// 'user'), which made the cloud-overview `entity_type = 'cloud_account'`
/// fan-out structurally empty. Every other type keeps the v1 value inference
/// so scores/groupings are unchanged (design §3: read inference is not swapped
/// mid-migration; findings without the stamp — pre-NAN-1806 rows — fall
/// through to the value branches).
const ENTITY_SELECT_COLS: &str = r#"                    __RISK_ENTITY__ as entity,
                    -- Infer entity type from the value; honor the write-side
                    -- stamp for cloud_account only (NAN-1806)
                    multiIf(
                        __RISK_ENTITY_TYPE__ = 'cloud_account', 'cloud_account',
                        match(__RISK_ENTITY__, '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'), 'ip',
                        position(__RISK_ENTITY__, '@') > 0, 'email',
                        position(__RISK_ENTITY__, '.') > 0, 'hostname',
                        'user'
                    ) as entity_type,
                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    __RULE_NAME__ as rule_name,
                    __SEVERITY__ as severity,
                    -- Calculate decay factor based on signal age
"#;

/// `signal_scores` SELECT columns for the overview aggregate (trimmed to what
/// the banding needs — no entity-type inference or last-* columns).
const OVERVIEW_SELECT_COLS: &str = r#"                    __RISK_ENTITY__ as entity,
                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
"#;

/// `signal_scores` SELECT columns for the per-rule contribution breakdown
/// (rule-grain: carries `rule_id`, drops the entity columns).
const CONTRIB_SELECT_COLS: &str = r#"                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    __RULE_ID__ as rule_id,
                    __RULE_NAME__ as rule_name,
                    __SEVERITY__ as severity,
"#;

/// Findings WHERE for the entity-grain queries: excludes empty/`unknown`
/// entities, bounds to the 7d horizon, applies the cleared-entity boundary.
/// Binds: `(cutoff_7d_us, boundaries_micros[], entities[])`.
const ENTITY_FINDINGS_WHERE: &str = r#"                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ != ''
                  AND __RISK_ENTITY__ != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  -- Cleared-entity boundary: for a cleared entity keep only
                  -- post-clear findings (ts > its boundary); everything else
                  -- falls through indexOf=0 -> arrayElement(_,0)=0 -> ts>0. (R4)
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, __RISK_ENTITY__))
            ),
"#;

/// Findings WHERE for the contribution breakdown: restricted to the supplied
/// entity values (no cleared boundary — the caller already resolved the
/// entity set). Binds: `(entities[], cutoff_7d_us)`.
const CONTRIB_FINDINGS_WHERE: &str = r#"                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ IN ?
                  AND toUnixTimestamp64Micro(timestamp) >= ?
            )
"#;

/// Entity-grain `aggregated` CTE + row projection.
/// Binds: `(cutoff_24h_us, cutoff_24h_us, cutoff_24h_us)`.
const ENTITY_AGGREGATED_SELECT: &str = r#"            aggregated AS (
                SELECT
                    entity,
                    entity_type,
                    -- Raw scores (no decay, for backwards compatibility)
                    sumIf(risk_score, ts_micros >= ?) as risk_score_24h,
                    sum(risk_score) as risk_score_7d,
                    -- Decayed scores (primary metric). round() (not truncating
                    -- toInt64) so the headline matches the per-rule contribution
                    -- breakdown, which also rounds (NAN-1658 / R3).
                    toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_score_24h,
                    toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d,
                    countIf(ts_micros >= ?) as signal_count_24h,
                    count() as signal_count_7d,
                    max(ts_micros) as last_signal_at,
                    argMax(rule_name, ts_micros) as last_rule_name,
                    argMax(severity, ts_micros) as last_severity
                FROM signal_scores
                GROUP BY entity, entity_type
            )
            SELECT
                entity,
                entity_type,
                risk_score_24h,
                risk_score_7d,
                decayed_score_24h,
                decayed_score_7d,
                signal_count_24h,
                signal_count_7d,
                last_signal_at,
                last_rule_name,
                last_severity
            FROM aggregated
"#;

/// Entity-grain `aggregated` CTE + row projection for the nPL `dataset=risk`
/// base source (NAN-1798 P2). SAME grain, GROUP BY, decay expressions, and
/// `round()` semantics as [`ENTITY_AGGREGATED_SELECT`] — `score_24h/7d` are the
/// EXACT `decayed_score_24h/7d` expressions, `raw_score_*`/`findings_*`/
/// `last_*` the exact raw-sum/count/argMax expressions — under the dataset's
/// public column names, plus the dataset-only distinct-rule/tactic widths
/// (`uniqIf(rule_id)` / `uniqArrayIf(tactics)`). `last_finding_at` converts the
/// shared `max(ts_micros)` to a DateTime64(6) so nPL time comparisons and the
/// default `ORDER BY last_finding_at DESC` read naturally. No selection tail —
/// filtering/ordering/limiting belong to the nPL pipeline composed on top.
/// Binds: `(cutoff_24h_us ×5)`.
const DATASET_AGGREGATED_SELECT: &str = r#"            aggregated AS (
                SELECT
                    entity,
                    entity_type,
                    -- Decayed scores (primary metric) — the same expressions as
                    -- decayed_score_24h/7d in ENTITY_AGGREGATED_SELECT (NAN-1658 / R3).
                    toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as score_24h,
                    toInt64(round(sum(risk_score * decay_factor))) as score_7d,
                    -- Raw (undecayed) sums — parity with TimeWindowedRiskScore.
                    sumIf(risk_score, ts_micros >= ?) as raw_score_24h,
                    sum(risk_score) as raw_score_7d,
                    countIf(ts_micros >= ?) as findings_24h,
                    count() as findings_7d,
                    uniqIf(rule_id, ts_micros >= ?) as distinct_rules_24h,
                    uniq(rule_id) as distinct_rules_7d,
                    uniqArrayIf(tactics, ts_micros >= ?) as distinct_tactics_24h,
                    uniqArray(tactics) as distinct_tactics_7d,
                    fromUnixTimestamp64Micro(max(ts_micros)) as last_finding_at,
                    argMax(rule_name, ts_micros) as last_rule_name,
                    argMax(severity, ts_micros) as last_severity
                FROM signal_scores
                GROUP BY entity, entity_type
            )
            SELECT
                entity,
                entity_type,
                score_24h,
                score_7d,
                raw_score_24h,
                raw_score_7d,
                findings_24h,
                findings_7d,
                distinct_rules_24h,
                distinct_rules_7d,
                distinct_tactics_24h,
                distinct_tactics_7d,
                last_finding_at,
                last_rule_name,
                last_severity
            FROM aggregated
"#;

/// Tail for [`EntityScoreSelection::MinScores`] (the Risk page entity list):
/// inclusive floors, hottest-first. Binds: `(min_24h, min_7d, limit)`.
const TAIL_MIN_SCORES: &str = r#"            WHERE decayed_score_24h >= ? OR decayed_score_7d >= ?
            ORDER BY decayed_score_24h DESC, decayed_score_7d DESC
            LIMIT ?
        "#;

/// Tail for the leaderboard (`get_risky_entities`, NAN-1798 P4): floor on the
/// window's decayed score, entities ACTIVE in the window only (`__SCOUNT__ >
/// 0` — mirrors the old PG `updated_at >= cutoff` window filter; a no-op for
/// the 7d window, where every CTE row has an in-window finding), optional
/// entity-type filter (spliced via `__TYPE_FILTER__`), hottest-first by the
/// same window's score then finding count — mirroring the old PG `ORDER BY
/// risk_score DESC, signal_count DESC` under the decayed metric.
/// Binds: `(min_score, [entity_type], limit, offset)`.
const TAIL_RISKY_ENTITIES: &str = r#"            WHERE __DSCORE__ >= ? AND __SCOUNT__ > 0__TYPE_FILTER__
            ORDER BY __DSCORE__ DESC, __SCOUNT__ DESC
            LIMIT ? OFFSET ?
        "#;

/// Tail for the dossier badge (`get_risk_for_entities`, NAN-1798 P4): the
/// single highest-scored identity, ranked by the 7d decayed score exactly as
/// the old PG reader ranked the persisted `decayed_score`. No binds.
const TAIL_TOP_BY_DECAYED_7D: &str = r#"            ORDER BY decayed_score_7d DESC
            LIMIT 1
        "#;

/// Findings WHERE for entity-grain queries restricted to an identity-resolved
/// entity set (dossier badge): [`ENTITY_FINDINGS_WHERE`] plus a verbatim
/// `entity IN` filter — the same matching the old PG reader's
/// `entity = ANY($1)` performed. Binds: `(entities[], cutoff_7d_us,
/// boundaries_micros[], entities[])`.
const ENTITY_FINDINGS_WHERE_IN: &str = r#"                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ != ''
                  AND __RISK_ENTITY__ != 'unknown'
                  AND __RISK_ENTITY__ IN ?
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  -- Cleared-entity boundary: for a cleared entity keep only
                  -- post-clear findings (ts > its boundary); everything else
                  -- falls through indexOf=0 -> arrayElement(_,0)=0 -> ts>0. (R4)
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, __RISK_ENTITY__))
            ),
"#;

/// Findings WHERE for the lateral-graph batch (NAN-1798 P4): the graph's node
/// ids are `normalize_id`'d (lowercased + FQDN-stripped) while `risk_entity`
/// is stored verbatim, so match on both the lowered form and the lowered
/// first DNS label — the same double-match the old PG reader performed with
/// `lower(entity) = ANY($1) OR lower(split_part(entity, '.', 1)) = ANY($1)`.
/// Binds: `(cutoff_7d_us, boundaries_micros[], entities[], ids[], ids[])`.
const LATERAL_FINDINGS_WHERE: &str = r#"                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ != ''
                  AND __RISK_ENTITY__ != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  -- Cleared-entity boundary (R4) — the persisted decayed_score
                  -- this replaces was zeroed on clear, so the batch honors the
                  -- same boundary.
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, __RISK_ENTITY__))
                  AND (
                      lower(__RISK_ENTITY__) IN ?
                      OR lower(arrayElement(splitByChar('.', __RISK_ENTITY__), 1)) IN ?
                  )
            ),
"#;

/// Lateral-graph `aggregated` CTE + projection: one 7d decayed score per
/// entity value — the recompute-on-read equivalent of the old PG
/// `MAX(decayed_score) GROUP BY entity`. No binds.
const LATERAL_AGGREGATED_SELECT: &str = r#"            aggregated AS (
                SELECT
                    entity,
                    toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d
                FROM signal_scores
                GROUP BY entity
            )
            SELECT entity, decayed_score_7d FROM aggregated
        "#;

/// Entity-type facet `aggregated` CTE + projection (`get_entity_types`,
/// NAN-1798 P4): distinct entities per inferred type over the 7d findings
/// window — the recompute-on-read equivalent of the old PG
/// `COUNT(*) GROUP BY entity_type` over the rollup rows (one row per
/// entity+type pair there ≙ one grouped entity here). Deterministic
/// tie-break on the type name. No binds.
const FACET_AGGREGATED_SELECT: &str = r#"            aggregated AS (
                SELECT entity, entity_type
                FROM signal_scores
                GROUP BY entity, entity_type
            )
            SELECT entity_type, count() as entity_count
            FROM aggregated
            GROUP BY entity_type
            ORDER BY entity_count DESC, entity_type ASC
        "#;

/// Overview `aggregated` CTE + band-count projection. `__DSCORE__` /
/// `__SCOUNT__` select the banding window (24h vs 7d columns); bands use the
/// same 30/50/70 thresholds as the frontend `getRiskLevel`.
/// Binds: `(cutoff_24h_us, cutoff_24h_us)`.
const OVERVIEW_AGGREGATED_SELECT: &str = r#"            aggregated AS (
                SELECT
                    entity,
                    toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_score_24h,
                    toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d,
                    countIf(ts_micros >= ?) as signal_count_24h,
                    count() as signal_count_7d
                FROM signal_scores
                GROUP BY entity
            )
            SELECT
                count() AS total_entities,
                countIf(__DSCORE__ > 70) AS critical_entities,
                countIf(__DSCORE__ > 50 AND __DSCORE__ <= 70) AS high_entities,
                countIf(__DSCORE__ > 30 AND __DSCORE__ <= 50) AS medium_entities,
                countIf(__DSCORE__ > 0 AND __DSCORE__ <= 30) AS low_entities,
                toInt64(sum(__SCOUNT__)) AS total_signals,
                if(count() > 0, avg(__DSCORE__), 0.0) AS avg_risk_score
            FROM aggregated
            WHERE __DSCORE__ > 0
        "#;

/// Rule-grain projection for the contribution breakdown (NAN-1658). Summing
/// `decayed_contribution_24h/7d` across the returned rules reproduces the
/// entity's `decayed_score_24h/7d` headline.
/// Binds: `(cutoff_24h_us, cutoff_24h_us)`.
const CONTRIB_FINAL_SELECT: &str = r#"            SELECT
                rule_id,
                argMax(rule_name, ts_micros) as rule_name,
                argMax(severity, ts_micros) as severity,
                countIf(ts_micros >= ?) as fires_24h,
                count() as fires_7d,
                toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_contribution_24h,
                toInt64(round(sum(risk_score * decay_factor))) as decayed_contribution_7d,
                max(ts_micros) as last_fire_at,
                argMax(risk_score, ts_micros) as last_fire_score
            FROM signal_scores
            GROUP BY rule_id
            ORDER BY decayed_contribution_7d DESC
            LIMIT 50
        "#;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// One bound parameter of a built risk query, in `?` placeholder order.
///
/// Variants mirror the exact Rust types the repository bound before the
/// extraction (`i64` cutoffs/limits, `f64` decay factors, string/int arrays
/// for the cleared boundary and entity sets) so the client-side serialization
/// is unchanged.
#[derive(Debug, Clone, PartialEq)]
pub enum RiskSqlBind {
    I64(i64),
    F64(f64),
    Str(String),
    StrList(Vec<String>),
    I64List(Vec<i64>),
}

/// A built ClickHouse risk statement: SQL with `?` placeholders plus its
/// ordered binds. Keeping the binds structurally attached to the SQL is the
/// point — placeholder order and bind order can no longer drift apart.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskChQuery {
    pub sql: String,
    pub binds: Vec<RiskSqlBind>,
}

impl RiskChQuery {
    /// Bind every parameter onto `client`, ready to fetch.
    pub fn to_clickhouse_query(&self, client: &clickhouse::Client) -> clickhouse::query::Query {
        let mut query = client.query(&self.sql);
        for bind in &self.binds {
            query = match bind {
                RiskSqlBind::I64(v) => query.bind(*v),
                RiskSqlBind::F64(v) => query.bind(*v),
                RiskSqlBind::Str(v) => query.bind(v.as_str()),
                RiskSqlBind::StrList(v) => query.bind(v.as_slice()),
                RiskSqlBind::I64List(v) => query.bind(v.as_slice()),
            };
        }
        query
    }

    /// Render the statement with every bind inlined as a ClickHouse literal, in
    /// placeholder order — for callers that execute plain SQL strings rather
    /// than client-bound queries (the nPL `dataset=risk` derived base source,
    /// NAN-1798 P2). Values render exactly as the client-side binder would send
    /// them: integers bare, floats with a decimal point (so a `1.0` decay
    /// factor stays Float64), string arrays as `['…', …]` with
    /// [`escape_sql_string`](crate::sql_hygiene::escape_sql_string) escaping.
    /// None of the fragment templates contain `?` inside string literals or
    /// comments, so sequential substitution is exact (asserted by tests).
    pub fn to_inline_sql(&self) -> String {
        debug_assert_eq!(
            self.sql.matches('?').count(),
            self.binds.len(),
            "placeholder/bind count mismatch in risk SQL"
        );
        let mut out = String::with_capacity(self.sql.len() + 64 * self.binds.len());
        let mut binds = self.binds.iter();
        let mut pieces = self.sql.split('?').peekable();
        while let Some(piece) = pieces.next() {
            out.push_str(piece);
            if pieces.peek().is_none() {
                break;
            }
            match binds.next() {
                // Fewer binds than placeholders is a builder bug; keep the raw
                // `?` so the statement fails loudly instead of silently gluing
                // the surrounding SQL together.
                None => out.push('?'),
                Some(bind) => match bind {
                    RiskSqlBind::I64(v) => out.push_str(&v.to_string()),
                    // `{:?}` keeps a decimal point on round floats ("1.0", not
                    // "1"), preserving Float64 typing in the multiIf branches.
                    RiskSqlBind::F64(v) => out.push_str(&format!("{v:?}")),
                    RiskSqlBind::Str(v) => out.push_str(&format!(
                        "'{}'",
                        crate::sql_hygiene::escape_sql_string(v)
                    )),
                    RiskSqlBind::StrList(v) => {
                        let items = v
                            .iter()
                            .map(|s| format!("'{}'", crate::sql_hygiene::escape_sql_string(s)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        out.push_str(&format!("[{items}]"));
                    }
                    RiskSqlBind::I64List(v) => {
                        let items = v
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        out.push_str(&format!("[{items}]"));
                    }
                },
            }
        }
        out
    }
}

/// Where finding rows live and how the nano risk fields are read.
///
/// Under the OCSF profile, findings are OCSF Detection Finding (class_uid
/// 2004) rows and the nano fields are read from the stored `unmapped` spill
/// (NAN-1443; `event` is EPHEMERAL); under UDM they are real columns. The
/// table is the cluster-aware **read** name (`_distributed` wrapper when
/// clustered) so scans fan out across shards (R7).
#[derive(Debug, Clone, PartialEq)]
pub struct RiskFindingsSource {
    ocsf: bool,
    logs_table: String,
}

impl RiskFindingsSource {
    /// Explicit construction (tests, callers that already resolved profile
    /// and table routing).
    pub fn new(ocsf: bool, logs_table: impl Into<String>) -> Self {
        Self {
            ocsf,
            logs_table: logs_table.into(),
        }
    }

    /// Resolve from the active schema profile (env) and cluster topology —
    /// the same resolution the repository performed inline before the
    /// extraction.
    pub fn resolve(is_clustered: bool) -> Self {
        let ocsf = crate::schema::active_profile_from_env()
            .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
            .unwrap_or(false);
        let logs_table =
            crate::db::TableNames::new(is_clustered).read_bare(crate::schema::active_logs_table());
        Self { ocsf, logs_table }
    }

    fn entity_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtractString(toString(unmapped),'risk_entity')"
        } else {
            "risk_entity"
        }
    }

    fn score_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtractInt(toString(unmapped), 'risk_score')"
        } else {
            "risk_score"
        }
    }

    fn rule_name_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtractString(toString(unmapped), 'rule_name')"
        } else {
            "rule_name"
        }
    }

    fn rule_id_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtractString(toString(unmapped),'rule_id')"
        } else {
            "rule_id"
        }
    }

    fn severity_col(&self) -> &'static str {
        if self.ocsf {
            "lower(severity)"
        } else {
            "severity"
        }
    }

    /// The write-side entity-type stamp (`risk_entity_type`, NAN-1806). UDM
    /// findings carry it in the `metadata` JSON string (`Finding::to_log_json`);
    /// OCSF findings carry it in the stored `unmapped` vendor extension
    /// (`build_ocsf_finding_event`). Pre-stamp rows extract as `''` and fall
    /// through to the value inference.
    fn stamped_type_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtractString(toString(unmapped),'risk_entity_type')"
        } else {
            "JSONExtractString(metadata, 'risk_entity_type')"
        }
    }

    /// The finding's MITRE tactic list (`Array(String)`), for the nPL
    /// `dataset=risk` distinct-tactics widths (NAN-1798 P2). UDM findings carry
    /// it in the `metadata` JSON string (`Finding::to_log_json`); OCSF findings
    /// carry it in the stored `unmapped` vendor extension
    /// (`build_ocsf_finding_event`) — the same spill the risk fields read from.
    fn tactics_col(&self) -> &'static str {
        if self.ocsf {
            "JSONExtract(toString(unmapped), 'mitre_tactics', 'Array(String)')"
        } else {
            "JSONExtract(metadata, 'mitre_tactics', 'Array(String)')"
        }
    }

    /// Replace the column/table sentinels in an assembled template.
    /// `__RISK_ENTITY_TYPE__` must substitute BEFORE `__RISK_ENTITY__`
    /// (the former contains the latter as a prefix).
    fn substitute(&self, template: String) -> String {
        template
            .replace("__RISK_ENTITY_TYPE__", self.stamped_type_col())
            .replace("__RISK_ENTITY__", self.entity_col())
            .replace("__RISK_SCORE__", self.score_col())
            .replace("__RULE_NAME__", self.rule_name_col())
            .replace("__RULE_ID__", self.rule_id_col())
            .replace("__SEVERITY__", self.severity_col())
            .replace("__MITRE_TACTICS__", self.tactics_col())
            .replace("__LOGS_TBL__", &self.logs_table)
    }
}

/// The `(entities, boundary_micros)` parallel arrays that drive the in-SQL
/// cleared-boundary filter. A trailing sentinel (the empty entity, already
/// excluded by `risk_entity != ''`) guarantees the arrays are non-empty so
/// ClickHouse can type `indexOf` / `arrayElement` even when nothing is
/// cleared. For a cleared entity the finding is kept only when
/// `ts > boundary`; for anything not in the set `indexOf` returns 0,
/// `arrayElement(_, 0)` yields the default 0, and `ts > 0` keeps the row.
#[derive(Debug, Clone, PartialEq)]
pub struct ClearedBoundaries {
    entities: Vec<String>,
    boundaries_micros: Vec<i64>,
}

impl ClearedBoundaries {
    /// Build from the value-keyed clear map (`get_cleared_entities`).
    pub fn from_map(cleared: &HashMap<String, DateTime<Utc>>) -> Self {
        let mut entities = Vec::with_capacity(cleared.len() + 1);
        let mut boundaries_micros = Vec::with_capacity(cleared.len() + 1);
        for (entity, cleared_at) in cleared {
            entities.push(entity.clone());
            boundaries_micros.push(cleared_at.timestamp_micros());
        }
        entities.push(String::new());
        boundaries_micros.push(0);
        Self {
            entities,
            boundaries_micros,
        }
    }

    pub fn entities(&self) -> &[String] {
        &self.entities
    }

    pub fn boundaries_micros(&self) -> &[i64] {
        &self.boundaries_micros
    }
}

/// Final row selection for the entity-grain score query.
///
/// (The `ExceedsThresholds` variant — the retired `RiskNotableScheduler`'s
/// candidate view, last served by `GET /api/risk/thresholds` — was removed in
/// NAN-1806 after P3 made risk alerting a `dataset=risk` detection rule.)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntityScoreSelection {
    /// Inclusive floors ordered hottest-first — the Risk page entity list
    /// (`get_time_windowed_risk_scores`).
    MinScores {
        min_score_24h: i64,
        min_score_7d: i64,
        limit: i64,
    },
}

/// Microsecond cutoffs for the decay buckets, anchored at `now`.
struct DecayCutoffs {
    cutoff_24h_us: i64,
    cutoff_3d_us: i64,
    cutoff_5d_us: i64,
    cutoff_7d_us: i64,
}

impl DecayCutoffs {
    fn at(now: DateTime<Utc>) -> Self {
        Self {
            cutoff_24h_us: (now - Duration::hours(24)).timestamp_micros(),
            cutoff_3d_us: (now - Duration::hours(72)).timestamp_micros(),
            cutoff_5d_us: (now - Duration::hours(120)).timestamp_micros(),
            cutoff_7d_us: (now - Duration::hours(168)).timestamp_micros(),
        }
    }
}

/// Binds for [`DECAY_FACTOR_EXPR`], in placeholder order.
fn decay_factor_binds(cutoffs: &DecayCutoffs, decay: &RiskDecayConfig) -> Vec<RiskSqlBind> {
    vec![
        RiskSqlBind::I64(cutoffs.cutoff_24h_us),
        RiskSqlBind::F64(decay.decay_0_24h),
        RiskSqlBind::I64(cutoffs.cutoff_3d_us),
        RiskSqlBind::F64(decay.decay_1_3d),
        RiskSqlBind::I64(cutoffs.cutoff_5d_us),
        RiskSqlBind::F64(decay.decay_3_5d),
        RiskSqlBind::I64(cutoffs.cutoff_7d_us),
        RiskSqlBind::F64(decay.decay_5_7d),
    ]
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Entity-grain decayed score query (one row per entity): raw + decayed
/// 24h/7d sums, finding counts, and last-fire metadata, filtered/ordered per
/// `selection`. This is the canonical accumulated-risk computation — the Risk
/// page list and the alerting threshold view are the same statement with
/// different tails.
pub fn entity_scores_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
    selection: EntityScoreSelection,
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(ENTITY_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE);
    sql.push_str(ENTITY_AGGREGATED_SELECT);
    sql.push_str(match selection {
        EntityScoreSelection::MinScores { .. } => TAIL_MIN_SCORES,
    });

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    // ENTITY_FINDINGS_WHERE: 7d horizon, then boundary/entity arrays in
    // `arrayElement(?, indexOf(?, …))` placeholder order.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    // ENTITY_AGGREGATED_SELECT: 24h bounds for raw sum, decayed sum, count.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    match selection {
        EntityScoreSelection::MinScores {
            min_score_24h,
            min_score_7d,
            limit,
        } => {
            binds.push(RiskSqlBind::I64(min_score_24h));
            binds.push(RiskSqlBind::I64(min_score_7d));
            binds.push(RiskSqlBind::I64(limit));
        }
    }

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// The `(decayed score, finding count)` column pair a [`RiskTimeWindow`]
/// selects on the entity-grain projection: `Last24Hours` → the 24h columns,
/// `Last7Days`/`All` → the 7d columns. The findings horizon is 7 days, so
/// `All` deliberately equals `Last7Days` — the design's leaderboard pivot
/// from the retired cumulative accumulator to the decayed sums (NAN-1798 P4).
fn window_columns(window: RiskTimeWindow) -> (&'static str, &'static str) {
    if matches!(window, RiskTimeWindow::Last24Hours) {
        ("decayed_score_24h", "signal_count_24h")
    } else {
        ("decayed_score_7d", "signal_count_7d")
    }
}

/// Leaderboard query (`get_risky_entities` / `GET /api/risk/entities`,
/// NAN-1798 P4): the SAME entity-grain decayed computation as
/// [`entity_scores_query`], selected/ordered on the `window`'s decayed score
/// with an optional entity-type filter and LIMIT/OFFSET pagination — replacing
/// the retired PG read of the cumulative `entity_risk_scores` accumulator.
/// Same projection (deserializes into the same row type).
#[allow(clippy::too_many_arguments)]
pub fn risky_entities_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
    window: RiskTimeWindow,
    entity_type: Option<&str>,
    min_score: i64,
    limit: i64,
    offset: i64,
) -> RiskChQuery {
    let (dscore, scount) = window_columns(window);

    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(ENTITY_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE);
    sql.push_str(ENTITY_AGGREGATED_SELECT);
    sql.push_str(TAIL_RISKY_ENTITIES);
    let sql = sql
        .replace("__DSCORE__", dscore)
        .replace("__SCOUNT__", scount)
        .replace(
            "__TYPE_FILTER__",
            if entity_type.is_some() {
                " AND entity_type = ?"
            } else {
                ""
            },
        );

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    // TAIL_RISKY_ENTITIES: floor, optional type filter, limit, offset.
    binds.push(RiskSqlBind::I64(min_score));
    if let Some(entity_type) = entity_type {
        binds.push(RiskSqlBind::Str(entity_type.to_string()));
    }
    binds.push(RiskSqlBind::I64(limit));
    binds.push(RiskSqlBind::I64(offset));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Dossier-badge query (`get_risk_for_entities`, NAN-1798 P4): the single
/// highest-risk row across an identity-resolved entity set, ranked by the 7d
/// decayed score — the live recompute of the retired PG reader's
/// `ORDER BY decayed_score DESC LIMIT 1` over the 15-min sweep snapshot.
/// Same entity-grain projection as [`entity_scores_query`].
pub fn risk_for_entities_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
    entities: &[String],
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(ENTITY_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE_IN);
    sql.push_str(ENTITY_AGGREGATED_SELECT);
    sql.push_str(TAIL_TOP_BY_DECAYED_7D);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    // ENTITY_FINDINGS_WHERE_IN: entity set precedes the 7d horizon, then the
    // boundary/entity arrays in `arrayElement(?, indexOf(?, …))` order.
    binds.push(RiskSqlBind::StrList(entities.to_vec()));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    // ENTITY_AGGREGATED_SELECT: 24h bounds for raw sum, decayed sum, count.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Entity-type facet query (`get_entity_types` / `GET /api/risk/overview`,
/// NAN-1798 P4): distinct entities per inferred type over the same
/// `signal_scores` scan as [`entity_scores_query`] — so the facet counts the
/// exact entity set the leaderboard/entity list shows, instead of the retired
/// all-time PG rollup rows. (The decay column rides along in the shared CTE;
/// ClickHouse prunes it from the unaggregated projection.)
pub fn entity_types_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(ENTITY_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE);
    sql.push_str(FACET_AGGREGATED_SELECT);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Lateral-graph risk batch (NAN-1798 P4): one 7d decayed score per matching
/// entity value, restricted in SQL to the graph's normalized node ids
/// (lowered, or lowered first DNS label — the FQDN double-match the retired
/// PG reader performed). One batched statement for the whole node set; the
/// caller maps entity values back to normalized ids.
///
/// `normalized_ids` MUST already be `normalize_id`'d (lowercase) — the SQL
/// lowers only the stored entity side.
pub fn lateral_scores_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
    normalized_ids: &[String],
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(OVERVIEW_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(LATERAL_FINDINGS_WHERE);
    sql.push_str(LATERAL_AGGREGATED_SELECT);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    // LATERAL_FINDINGS_WHERE: the id set twice (lowered entity, lowered first
    // DNS label).
    binds.push(RiskSqlBind::StrList(normalized_ids.to_vec()));
    binds.push(RiskSqlBind::StrList(normalized_ids.to_vec()));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Decayed risk overview aggregate: entity counts per severity band
/// (30/50/70), total findings, and average score over the SAME decayed
/// computation as [`entity_scores_query`], banded on the `window`'s decayed
/// field (`Last24Hours` → 24h, else 7d).
pub fn decayed_overview_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
    window: RiskTimeWindow,
) -> RiskChQuery {
    let (dscore, scount) = if matches!(window, RiskTimeWindow::Last24Hours) {
        ("decayed_score_24h", "signal_count_24h")
    } else {
        ("decayed_score_7d", "signal_count_7d")
    };

    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(OVERVIEW_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE);
    sql.push_str(OVERVIEW_AGGREGATED_SELECT);
    let sql = sql.replace("__DSCORE__", dscore).replace("__SCOUNT__", scount);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    // OVERVIEW_AGGREGATED_SELECT: 24h bounds for decayed sum and count.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Exact per-rule contributions to the given entities' decayed scores
/// (NAN-1658): same source, window, and decay curve as
/// [`entity_scores_query`], grouped by rule. No cleared-boundary or
/// empty/`unknown` filters — the caller supplies the resolved entity set.
pub fn rule_contributions_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    entities: &[String],
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(CONTRIB_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(CONTRIB_FINDINGS_WHERE);
    sql.push_str(CONTRIB_FINAL_SELECT);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    // CONTRIB_FINDINGS_WHERE: entity IN-set precedes the 7d horizon.
    binds.push(RiskSqlBind::StrList(entities.to_vec()));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    // CONTRIB_FINAL_SELECT: 24h bounds for fire count and decayed sum.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// Entity-grain derived base source for the nPL `dataset=risk` (NAN-1798 P2):
/// one row per entity with the dataset's public column universe (`entity`,
/// `entity_type`, `score_24h/7d`, `raw_score_24h/7d`, `findings_24h/7d`,
/// `distinct_rules_24h/7d`, `distinct_tactics_24h/7d`, `last_finding_at`,
/// `last_rule_name`, `last_severity`).
///
/// Composes the SAME fragments as [`entity_scores_query`] — CTE open, entity
/// select columns, decay `multiIf`, findings WHERE with the cleared-entity
/// boundary — plus the dataset-only `rule_id`/`tactics` inputs, so the decayed
/// `score_24h`/`score_7d` an nPL query sees are structurally the SAME
/// computation as the Risk page / leaderboard (`decayed_score_24h/7d`), never a
/// re-derivation. No selection tail: filtering/ordering/limiting compose in the
/// nPL pipeline on top of this source.
pub fn risk_dataset_base_query(
    source: &RiskFindingsSource,
    now: DateTime<Utc>,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
) -> RiskChQuery {
    let mut sql = String::new();
    sql.push_str(CTE_OPEN);
    sql.push_str(DATASET_EXTRA_SELECT_COLS);
    sql.push_str(ENTITY_SELECT_COLS);
    sql.push_str(DECAY_FACTOR_EXPR);
    sql.push_str(ENTITY_FINDINGS_WHERE);
    sql.push_str(DATASET_AGGREGATED_SELECT);

    let cutoffs = DecayCutoffs::at(now);
    let mut binds = decay_factor_binds(&cutoffs, decay);
    // ENTITY_FINDINGS_WHERE: 7d horizon, then boundary/entity arrays in
    // `arrayElement(?, indexOf(?, …))` placeholder order.
    binds.push(RiskSqlBind::I64(cutoffs.cutoff_7d_us));
    binds.push(RiskSqlBind::I64List(cleared.boundaries_micros.clone()));
    binds.push(RiskSqlBind::StrList(cleared.entities.clone()));
    // DATASET_AGGREGATED_SELECT: 24h bounds for decayed sum, raw sum, finding
    // count, distinct rules, distinct tactics.
    for _ in 0..5 {
        binds.push(RiskSqlBind::I64(cutoffs.cutoff_24h_us));
    }

    RiskChQuery {
        sql: source.substitute(sql),
        binds,
    }
}

/// The per-request configuration the nPL `dataset=risk` base source is built
/// from (NAN-1798 P2): the SAME decay factors and cleared-entity boundaries
/// the enterprise `RiskRepository` binds, plus the evaluation anchor for the
/// fixed trailing 24h/7d windows. Resolved per request by the cached
/// [`RiskQueryConfigProvider`](super::config_provider::RiskQueryConfigProvider)
/// and handed to the SQL generator by `core_search`.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskQueryConfig {
    pub decay: RiskDecayConfig,
    pub cleared: ClearedBoundaries,
    /// Anchor for the decay-bucket cutoffs and the trailing 24h/7d windows —
    /// generation time in production; pinned by tests for deterministic SQL.
    pub now: DateTime<Utc>,
}

impl Default for RiskQueryConfig {
    /// Built-in defaults (shipped decay curve, nothing cleared, anchored at
    /// `Utc::now()`): the fallback when a generator is pointed at the risk
    /// dataset without a resolved per-request config — e.g. a bare
    /// `with_dataset(Risk)` in tests. `core_search` always resolves the real
    /// config so production scores match the Risk page / leaderboard.
    fn default() -> Self {
        Self {
            decay: RiskDecayConfig::default(),
            cleared: ClearedBoundaries::from_map(&HashMap::new()),
            now: Utc::now(),
        }
    }
}

#[cfg(test)]
#[path = "clickhouse_sql_tests.rs"]
mod clickhouse_sql_tests;
