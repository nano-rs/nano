// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where detection matches land, as one SQL source (NAN-5543).

use crate::schema::SchemaId;

/// Every detection that fired in the sweep window, as ONE window-bound
/// subquery shaped like the ClickHouse `signals` table (NAN-5543).
///
/// Detection matches land in two places:
/// - real-time rules (materialized views) write `signals` rows;
/// - scheduled rules, in live and alerting mode, write ONLY a findings row
///   into the event table (`FindingLogger::log_to_clickhouse`): under OCSF an
///   OCSF Detection Finding (`class_uid = 2004`, `source_type = 'findings'`)
///   in `ocsf_logs`, with the rule in `finding_info.uid` / `finding_info.title`
///   and the nano fields in the stored `unmapped` extension; under UDM a
///   `logs` row with `source_type = 'findings'`, explicit `rule_id`,
///   `rule_name`, `severity`, `risk_score` and `risk_entity` columns and the
///   rest in the `metadata` JSON.
///
/// The signal processor ALSO logs a findings row for every real-time match
/// (`realtime = true`), so the findings leg keeps only `realtime = false`
/// rows: each detection appears exactly once.
///
/// Columns: `id`, `timestamp` (DateTime64(6)), `rule_id` (UUID), `rule_name`,
/// `severity` (lowercase), `risk_score`, `risk_entity`, `matched_log_id` (the
/// signal's matched event; a finding's first sampled event, zero UUID when it
/// has none), `source_type` (the matched event's source; `findings` when a
/// finding does not record one) and `detection_path` (`realtime` |
/// `scheduled`). Both legs carry the window (`window_start` / `window_end`
/// are SQL expressions: the lane's bound parameters, or server-formatted
/// literals), so the source is window-bound wherever it is read.
///
/// `{signals}` in a `dataset: signals` pivot exposes exactly these ten
/// columns (not `signals.metadata` / `_inserted_at`).
///
/// Every read of "the detections that fired" goes through this: `signals`
/// pivots (`{signals}`), the related-signals preload (investigator pivots and
/// the reviewer), the discover probe, and the server's check of a finding's
/// `matched_signal_id` (so a duplicate of a SCHEDULED detection holds).
pub fn detections_source_between(
    signals_table: &str,
    events_table: &str,
    schema: SchemaId,
    window_start: &str,
    window_end: &str,
) -> String {
    detections_source_scoped(signals_table, events_table, schema, window_start, window_end, &DetectionsScope::default())
}

/// Who reads [`detections_source_scoped`]: the caller's per-source RBAC
/// deny set (NAN-5612). The default (empty) scope is unrestricted and leaves
/// the SQL byte-identical to [`detections_source_between`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionsScope {
    /// Normalized (trimmed, lowercased, non-empty) denied `source_type`s.
    denied: std::collections::BTreeSet<String>,
}

impl DetectionsScope {
    /// Build from a caller's deny set (any casing; empties dropped).
    pub fn from_denied<'a>(denied: impl IntoIterator<Item = &'a String>) -> Self {
        Self {
            denied: denied
                .into_iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.denied.is_empty()
    }

    /// A per-source RBAC restriction beyond the `audit` row gate (which every
    /// principal without `audit:view` carries). Such a caller is source-scoped:
    /// a detection whose provenance is unknown (a pre-164 real-time signal
    /// stamped `unknown`, a finding with no recorded origin) could come from
    /// a denied source, so it is hidden (fail closed, the tuning-manifest
    /// posture of `auth::scope`). An audit-only caller keeps seeing them, the
    /// `'{}'`-visible posture of alerts and detection matches.
    pub fn is_source_scoped(&self) -> bool {
        self.denied.iter().any(|s| s != "audit")
    }

    /// `'a', 'b'` for the deny list, plus the unresolved-provenance sentinel.
    fn deny_list(&self) -> String {
        let mut values: Vec<String> = self.denied.iter().cloned().collect();
        values.push(crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string());
        values.sort();
        values.dedup();
        values
            .iter()
            .map(|v| crate::sql_hygiene::string_literal(v))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The real-time leg's extra predicate (`s.source_type` is one value).
    fn realtime_predicate(&self) -> String {
        if self.is_unrestricted() {
            return String::new();
        }
        let mut p = format!(" AND lower(trimBoth(s.source_type)) NOT IN ({})", self.deny_list());
        if self.is_source_scoped() {
            p.push_str(" AND lower(trimBoth(s.source_type)) NOT IN ('', 'unknown')");
        }
        p
    }

    /// The scheduled leg's extra predicate over the finding's FULL origin
    /// manifest (`origin_source_types`, every source the match drew on), not
    /// just the first entry the `source_type` column shows: a finding that
    /// drew on ANY denied source is hidden.
    fn scheduled_predicate(&self, origins: &str) -> String {
        if self.is_unrestricted() {
            return String::new();
        }
        let lowered = format!("arrayMap(x -> lower(trimBoth(x)), {origins})");
        let mut p = format!(" AND NOT hasAny({lowered}, [{}])", self.deny_list());
        if self.is_source_scoped() {
            // `unknown` is the same no-provenance sentinel the real-time leg
            // hides: a finding whose only origins are '' / 'unknown' could
            // come from a denied source.
            p.push_str(&format!(" AND notEmpty(arrayFilter(x -> x NOT IN ('', 'unknown'), {lowered}))"));
        }
        p
    }
}

/// [`detections_source_between`] for a scoped reader (NAN-5612, the
/// `dataset=signals` Search dataset): the same ten columns and window, with
/// the caller's deny set applied INSIDE both legs (see [`DetectionsScope`]).
/// Unrestricted is byte-identical to [`detections_source_between`].
pub fn detections_source_scoped(
    signals_table: &str,
    events_table: &str,
    schema: SchemaId,
    window_start: &str,
    window_end: &str,
    scope: &DetectionsScope,
) -> String {
    let window = |alias: &str| format!("{alias}.timestamp >= {window_start} AND {alias}.timestamp <= {window_end}");
    let realtime = format!(
        "SELECT s.id AS id, s.timestamp AS timestamp, s.rule_id AS rule_id, s.rule_name AS rule_name, \
                s.severity AS severity, toInt64(s.risk_score) AS risk_score, s.risk_entity AS risk_entity, \
                s.matched_log_id AS matched_log_id, s.source_type AS source_type, 'realtime' AS detection_path \
           FROM {signals_table} AS s WHERE {}{}",
        window("s"),
        scope.realtime_predicate()
    );
    // The second leg takes the first leg's column names (UNION ALL), so it
    // carries no aliases that could shadow its own columns in WHERE.
    let scheduled = if schema == SchemaId::Ocsf {
        let unmapped = |path: &str| format!("ifNull(toJSONString(f.unmapped.{path}), 'null')");
        format!(
            "SELECT f.id, toDateTime64(f.timestamp, 6, 'UTC'), toUUIDOrZero(f.`finding_info.uid`), \
                    f.`finding_info.title`, lower(f.severity), JSONExtractInt({score}), JSONExtractString({entity}), \
                    toUUIDOrZero(JSONExtractString({sample}, 1, 'id')), \
                    ifNull(nullIf(JSONExtract({origin}, 'Array(String)')[1], ''), 'findings'), 'scheduled' \
               FROM {events_table} AS f \
              WHERE f.class_uid = 2004 AND f.source_type = 'findings' AND {window} \
                AND NOT JSONExtractBool({realtime}){scoped}",
            score = unmapped("risk_score"),
            entity = unmapped("risk_entity"),
            sample = unmapped("matched_events_sample"),
            origin = unmapped("origin_source_types"),
            realtime = unmapped("realtime"),
            window = window("f"),
            scoped = scope.scheduled_predicate(&format!("JSONExtract({}, 'Array(String)')", unmapped("origin_source_types"))),
        )
    } else {
        format!(
            "SELECT f.id, f.timestamp, toUUIDOrZero(f.rule_id), f.rule_name, lower(f.severity), \
                    toInt64(f.risk_score), f.risk_entity, \
                    toUUIDOrZero(JSONExtractString(f.metadata, 'matched_events_sample', 1, 'id')), \
                    ifNull(nullIf(JSONExtract(f.metadata, 'origin_source_types', 'Array(String)')[1], ''), 'findings'), \
                    'scheduled' \
               FROM {events_table} AS f \
              WHERE f.source_type = 'findings' AND {window} AND NOT JSONExtractBool(f.metadata, 'realtime'){scoped}",
            window = window("f"),
            scoped = scope.scheduled_predicate("JSONExtract(f.metadata, 'origin_source_types', 'Array(String)')"),
        )
    };
    format!("({realtime} UNION ALL {scheduled})")
}

