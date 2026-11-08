// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — server-side evidence resolution.
//!
//! # Why this exists at all
//!
//! A sweep report names events by identifier. Everything the server later
//! derives — the provenance manifest, the corroborated entity, the evidence
//! count and cross-source corroboration that feed the score — has to come from
//! rows the SERVER read, not from anything the agent asserted about them. If the
//! agent could describe its own evidence, "the score is mechanical" would be a
//! slogan: the model's context is full of attacker-authored log content, so the
//! thing being hunted would get a say in how interesting it is.
//!
//! So the report's `evidence_event_ids` are treated as *pointers into
//! ClickHouse and nothing else*. Each one is parsed as a UUID (the `logs.id`
//! type) before it reaches SQL — not escaped, PARSED, so a value that is not a
//! UUID cannot reach the query in any form — and looked up under the sweep
//! principal's own source scope. What comes back is the whole truth the server
//! is willing to act on.
//!
//! # Why report-derived values are BOUND, never formatted
//!
//! Parsing and escaping were both correct, and both were still the weaker
//! claim: they say "this text was neutralised today". Every value this module
//! takes from a sweep report — the evidence ids and the lead's entity value —
//! now travels as a `clickhouse` bind argument, so it is not part of the query
//! TEXT at all and there is no escape for a future edit to forget. The
//! statement shapes are fixed strings; the only things interpolated into them
//! are server-owned (table names from [`crate::db::TableNames`], instants this
//! module formats itself, and the shared source-scope predicate).
//!
//! The one construct that cannot be bound is that source-scope predicate:
//! [`crate::search::service::source_scope_sql_predicate`] is the single
//! canonical builder for it (NAN-1801) and returns finished SQL with its deny
//! values already escaped in. Re-deriving it here to get binds would fork the
//! one shape every scoped read in the product shares, which is a worse trade —
//! so it stays interpolated, and [`escape_question_marks`] is applied to it
//! because a `?` reaching the driver from ANY interpolated literal is read as a
//! placeholder. See that function for the failure it prevents.
//!
//! # Fail-closed accounting
//!
//! [`ResolvedEvidence::provenance`] is complete only when EVERY requested id
//! resolved. An id that did not resolve is an event the narrative may have been
//! written from but whose origin the server cannot name — TTL'd out, deleted,
//! hallucinated, or denied to the sweep's principal. All four are the same
//! thing from a provenance standpoint: an unaccounted input. Claiming a
//! complete manifest over the survivors would under-report exactly the case the
//! manifest exists to catch.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::auth::{ScopeSet, SourceProvenance};
use crate::entity_extraction::EntityExtractor;
use crate::hunts::error::HuntError;

/// One event the server itself read out of the log store.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedEvent {
    /// `logs.id`, rendered canonically. Unique per lead by
    /// `uq_hunt_lead_evidence_canonical`, so a retried report is idempotent and
    /// the same event cannot be stacked to inflate an evidence count — and
    /// through it, a score.
    pub canonical_event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_type: String,
    /// A size-capped human line for the bench. The body deliberately stays in
    /// ClickHouse: a copy in Postgres would outlive both its retention and its
    /// ACL.
    pub summary: String,
    /// The raw row, kept only for entity extraction and the stored pointer.
    pub row: serde_json::Value,
    /// Entities extracted from THIS row.
    ///
    /// Recorded per event, not just unioned into the batch, because
    /// corroboration and evidence are different questions. The batch set proves
    /// a claimed entity appears somewhere; this proves which events actually
    /// mention it — and only those may count toward evidence volume, source
    /// diversity and the provenance manifest. Without the distinction, an agent
    /// attaching unrelated-but-readable events from several source types
    /// manufactures cross-source corroboration, the heaviest term in the score.
    pub entities: BTreeSet<(String, String)>,
}

/// The outcome of resolving one candidate's evidence list.
#[derive(Debug, Clone)]
pub struct ResolvedEvidence {
    pub events: Vec<ResolvedEvent>,
    /// `(entity_type, value)` pairs the server extracted from `events`. The
    /// corroboration set [`crate::hunts::fingerprint::CanonicalEntity::resolve`]
    /// checks a claimed entity against.
    pub observed_entities: BTreeSet<(String, String)>,
    /// Ids the report named that resolved to nothing readable.
    pub unresolved: Vec<String>,
}

impl ResolvedEvidence {
    /// Distinct source types across the resolved evidence — the corroboration
    /// input to [`crate::hunts::scoring::score`].
    pub fn distinct_source_types(&self) -> BTreeSet<String> {
        self.events
            .iter()
            .map(|e| e.source_type.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// The manifest to stamp on the lead.
    ///
    /// Complete only when nothing went unresolved — see the module docs. Note
    /// that this is also why an EMPTY evidence list yields an incomplete
    /// manifest: `SourceProvenance::complete` refuses to mark an empty manifest
    /// complete, so a lead with no evidence fails closed for every scoped
    /// reader rather than reading as "provably not source-derived".
    pub fn provenance(&self) -> SourceProvenance {
        let sources = self.distinct_source_types();
        if self.unresolved.is_empty() {
            SourceProvenance::complete(sources)
        } else {
            SourceProvenance::incomplete(sources)
        }
    }
}

/// Everything the scorer needs that only the log store can answer.
///
/// A trait, not a concrete struct, for one reason that matters: the commit path
/// must be testable without a ClickHouse. The invariants worth regression-
/// testing (an uncorroborated entity is rejected, a partially resolved evidence
/// list produces an incomplete manifest, a suppressed fingerprint zeroes the
/// score) are all about how the server COMBINES these answers, and none of them
/// should require a container to exercise.
#[async_trait::async_trait]
pub trait EvidenceResolver: Send + Sync {
    /// Resolve the report's event ids under the sweep principal's source scope.
    async fn resolve(
        &self,
        event_ids: &[String],
        scope: &ScopeSet,
    ) -> Result<ResolvedEvidence, HuntError>;

    /// Whether this entity has telemetry STRICTLY BEFORE `window_start`, within
    /// a bounded baseline lookback.
    ///
    /// Bounded deliberately: "has this ever been seen" over full retention is a
    /// 365-day scan per lead. The baseline window is the honest question a hunt
    /// can afford to ask, and the scorer's `first_seen` factor is worded as "no
    /// prior history for this entity" against it.
    async fn had_prior_history(
        &self,
        entity_type: &str,
        entity_value: &str,
        window_start: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<bool, HuntError>;

    /// Fraction of assets active in `[window_start, window_end]` that exhibited
    /// this entity, in `0.0..=1.0`.
    ///
    /// `None` means UNMEASURED, and the scorer treats it as such — an unknown
    /// prevalence is not evidence of rarity. Returning a guessed denominator
    /// here would manufacture excitement about an unmeasured entity, which is
    /// the precise failure [`crate::hunts::scoring`] documents.
    async fn asset_prevalence(
        &self,
        entity_type: &str,
        entity_value: &str,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<Option<f64>, HuntError>;

    /// Which of `candidates` have produced NO telemetry since `since`.
    ///
    /// A hunt whose required source is unhealthy is HELD rather than run
    /// partial, so yield stays comparable across sweeps — which means the rail
    /// has to be able to say WHICH source is the reason a hunt is quiet.
    /// Answering that from the log store is the only honest way: a source can be
    /// configured, deployed and healthy-looking in Postgres while nothing has
    /// arrived for a week.
    async fn silent_source_types(
        &self,
        candidates: &[String],
        since: DateTime<Utc>,
    ) -> Result<Vec<String>, HuntError>;
}

/// Hard ceiling on how many event ids one candidate may cite.
///
/// The report is attacker-influenceable through the model's context, and every
/// id becomes a row in the `IN` list and a potential `hunt_lead_evidence` row.
/// Bounding it here means the cap holds regardless of which caller grows next.
pub const MAX_EVIDENCE_IDS_PER_CANDIDATE: usize = 200;

/// How far back [`EvidenceResolver::had_prior_history`] looks. 30 days is long
/// enough that "new to the estate" means something and short enough to stay
/// inside partition pruning on a busy tenant.
pub const PRIOR_HISTORY_LOOKBACK_DAYS: i64 = 30;

/// Beyond this, prevalence is reported UNMEASURED rather than computed. The
/// prevalence query is a window scan; a hunt that opens with a 90-day lookback
/// should not silently turn one lead into a 90-day aggregate.
pub const MAX_PREVALENCE_WINDOW_DAYS: i64 = 7;

/// Cap on a stored evidence summary. Mirrors
/// `hunt_lead_evidence_summary_bounded` so the truncation happens where the
/// value is produced and the CHECK is never the thing that rejects a report.
const SUMMARY_MAX_CHARS: usize = 512;

/// Ceiling on a single ClickHouse response we buffer. Evidence lookups are
/// bounded by [`MAX_EVIDENCE_IDS_PER_CANDIDATE`] rows, so anything approaching
/// this is a malformed query rather than a large result.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// A UTC instant as a ClickHouse `DateTime64(6, 'UTC')` literal.
///
/// Explicitly `toDateTime64(…, 6, 'UTC')` rather than a bare string: a bare
/// integer compared against a `DateTime64(6)` column is interpreted as SECONDS
/// and silently matches the wrong window, and a bare string leaves the
/// precision to inference.
fn ch_instant(dt: &DateTime<Utc>) -> String {
    format!(
        "toDateTime64('{}', 6, 'UTC')",
        crate::sql_hygiene::format_ch_bound_micros(dt)
    )
}

/// The real resolver, reading `logs` through the runtime ClickHouse client.
pub struct ClickHouseEvidenceResolver {
    client: clickhouse::Client,
    logs_table: String,
    /// Resolves `_distributed` wrappers on a cluster. Reading a LOCAL rollup on
    /// a clustered tenant would see one shard's telemetry and report every
    /// source the other shards carry as silent.
    tables: crate::db::TableNames,
}

impl ClickHouseEvidenceResolver {
    pub fn new(pool: &crate::db::DualPool) -> Self {
        Self {
            client: pool.clickhouse().clone(),
            // `logs_distributed` on a cluster, `logs` otherwise. Reading the
            // local table on a clustered tenant would resolve only the shard we
            // happened to talk to, silently dropping evidence — and a silently
            // dropped event is scored as "not corroborated".
            logs_table: pool.logs_table().to_string(),
            tables: pool.table_names(),
        }
    }

    /// Build a resolver over an explicit ClickHouse client.
    ///
    /// [`Self::new`] needs a whole [`crate::db::DualPool`] — and therefore a
    /// reachable Postgres — to answer questions this type only ever asks of
    /// ClickHouse. The live tests in `evidence_tests.rs` exist to prove these
    /// statements EXECUTE, which a shape assertion cannot, so they need a way
    /// in that stops at the log store.
    #[cfg(test)]
    pub(crate) fn for_tests(client: clickhouse::Client, logs_table: &str) -> Self {
        Self {
            client,
            logs_table: logs_table.to_string(),
            tables: crate::db::TableNames::new(false),
        }
    }

    /// Run a JSONEachRow query with its bind arguments and return the parsed
    /// rows.
    ///
    /// `binds` are consumed by the `?` placeholders in `sql`, left to right.
    /// The `clickhouse` crate splits the template into literal/placeholder
    /// parts ONCE and substitutes each argument as an opaque part, so a bound
    /// value containing `?` is never rescanned as another placeholder — which
    /// is what makes binding, rather than escaping, the real fix for the URL
    /// query-string bug this module used to have.
    async fn fetch_json(
        &self,
        sql: &str,
        binds: &[Bound],
    ) -> Result<Vec<serde_json::Value>, HuntError> {
        let mut query = self.client.query(sql);
        for bound in binds {
            query = match bound {
                Bound::Text(value) => query.bind(value),
                Bound::TextList(values) => query.bind(values),
            };
        }
        let mut cursor = query
            .fetch_bytes("JSONEachRow")
            .map_err(|e| HuntError::LogStore(e.to_string()))?;

        let mut bytes = Vec::new();
        while let Some(chunk) = cursor
            .next()
            .await
            .map_err(|e| HuntError::LogStore(e.to_string()))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(HuntError::LogStore(
                    "evidence response exceeded the buffered response ceiling".to_string(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        let text =
            String::from_utf8(bytes).map_err(|e| HuntError::LogStore(format!("non-UTF8: {e}")))?;
        Ok(text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect())
    }

    /// The scope predicate, or `1 = 1` for an unrestricted reader.
    ///
    /// Emitting a tautology rather than skipping the clause keeps the generated
    /// SQL one shape, which is what makes the scoped and unscoped forms
    /// reviewable side by side. ClickHouse folds it away.
    ///
    /// This is the module's ONLY interpolated literal content, for the reason
    /// in the module docs: the canonical builder returns finished SQL. Its deny
    /// values are operator-configured source types rather than report content,
    /// but a `?` in one would still be read as a bind placeholder and error the
    /// whole probe out, so the result is question-mark escaped here.
    fn scope_clause(scope: &ScopeSet) -> String {
        escape_question_marks(
            &crate::search::service::source_scope_sql_predicate("source_type", scope.deny_set())
                .unwrap_or_else(|| "1 = 1".to_string()),
        )
    }
}

/// One value bound into a ClickHouse statement.
///
/// Text and text-list are the only shapes this module needs: every instant it
/// compares is server-formatted through [`ch_instant`], which carries the
/// `DateTime64(6)` precision the column actually has. Binding those as strings
/// instead would hand the precision back to inference — the bug
/// [`ch_instant`] documents.
#[derive(Debug, Clone, PartialEq)]
enum Bound {
    Text(String),
    /// Rendered by the driver as a ClickHouse array literal (`['a', 'b']`),
    /// which is a valid right-hand side for `IN`.
    TextList(Vec<String>),
}

/// The UDM columns each entity type may appear in.
///
/// Deliberately explicit rather than "search every column": a lead's entity has
/// to be corroborated in the field that MEANS that entity, or a hostname
/// appearing inside a command line would corroborate a claim about a host.
///
/// The returned expressions are compared against a single bind value, so every
/// one of them must be a column name — nothing here is caller-influenced.
///
/// Every name here must be a REAL column on `logs` (`clickhouse/init.sql`),
/// which is asserted by `every_probe_column_exists_in_the_logs_schema` in the
/// tests. NAN-2266: this listed `domain`, `dns_query`, `email_sender` and
/// `email_recipient` — none of which exist (the UDM names are `url_domain` /
/// `query` and `sender` / `recipient`) — so the FIRST domain or email lead a
/// sweep ever reported errored its prevalence probe at ClickHouse and 500'd
/// the whole report, stranding the sweep's lease with all its work unfiled.
fn entity_columns(entity_type: &str) -> &'static [&'static str] {
    match entity_type {
        "ip" => &["src_ip", "dest_ip"],
        "host" => &["src_host", "dest_host"],
        "user" => &["user", "src_user", "dest_user", "user_name"],
        // `query` is the UDM DNS query name; the *_domain columns are what the
        // entity extractor derives domain entities from, so history and
        // prevalence answer over the same fields corroboration used.
        "domain" => &["url_domain", "sender_domain", "recipient_domain", "query"],
        "hash" => &["file_hash", "process_hash"],
        "process" => &["process_name", "parent_process_name"],
        "file" => &["file_path", "file_name"],
        "url" => &["url"],
        "email" => &["sender", "recipient"],
        _ => &[],
    }
}

/// Whether comparisons for this entity type fold case.
///
/// Mirrors `fingerprint::CASE_INSENSITIVE_TYPES`. Hostnames, IPs, domains,
/// hashes and addresses compare case-insensitively; paths, URLs and command
/// lines do not, and folding them would let a probe about `/etc/Admin` answer a
/// question about `/etc/admin`.
fn folds_case(entity_type: &str) -> bool {
    matches!(entity_type, "ip" | "host" | "domain" | "hash" | "email")
}

/// A predicate fragment and the values its placeholders consume, in order.
///
/// The two travel together because they are only correct together: a caller
/// that emitted the SQL without binding exactly `binds.len()` arguments gets
/// `unbound query argument` from the driver rather than a wrong answer, but the
/// pairing is what stops that being possible in the first place.
#[derive(Debug, Clone, PartialEq)]
struct EntityProbe {
    sql: String,
    binds: Vec<Bound>,
}

/// Build the `(col = ? OR …)` disjunction for an entity, or `None` when the
/// type has no columns we can honestly probe.
///
/// The entity value is a BIND ARGUMENT, never query text. It arrives from a
/// sweep report — attacker-influenceable through the model's context — and the
/// previous escape-and-format form was correct but only as long as every future
/// edit remembered both escapes. A value that is not text cannot be neutralised
/// incorrectly.
///
/// Case-insensitive types compare via `lower(col)`, which is the form migration
/// 119's text indexes are built on — ClickHouse matches skip indexes by
/// EXPRESSION, so the exact indexed shape has to be emitted or the index is not
/// used at all. Folding happens on the BOUND value (`lower(col) = ?` with an
/// already-lowered argument) rather than by wrapping the argument in `lower()`,
/// so the right-hand side stays a constant the index can be probed with.
fn entity_predicate(entity_type: &str, value: &str) -> Option<EntityProbe> {
    let columns = entity_columns(entity_type);
    if columns.is_empty() {
        return None;
    }
    let fold = folds_case(entity_type);
    let needle = if fold {
        value.trim().to_lowercase()
    } else {
        value.trim().to_string()
    };
    let clauses: Vec<String> = columns
        .iter()
        .map(|col| {
            if fold {
                format!("lower({col}) = ?")
            } else {
                format!("{col} = ?")
            }
        })
        .collect();
    Some(EntityProbe {
        sql: format!("({})", clauses.join(" OR ")),
        // One argument per placeholder. The driver substitutes positionally, so
        // the value is repeated rather than named.
        binds: columns
            .iter()
            .map(|_| Bound::Text(needle.clone()))
            .collect(),
    })
}

#[async_trait::async_trait]
impl EvidenceResolver for ClickHouseEvidenceResolver {
    async fn resolve(
        &self,
        event_ids: &[String],
        scope: &ScopeSet,
    ) -> Result<ResolvedEvidence, HuntError> {
        // Parse, do not escape. `logs.id` is a UUID; anything that is not one
        // cannot name an event, so rejecting it here means no agent-authored
        // byte ever reaches the query text.
        let mut wanted: BTreeMap<Uuid, String> = BTreeMap::new();
        let mut unresolved: Vec<String> = Vec::new();
        for raw in event_ids.iter().take(MAX_EVIDENCE_IDS_PER_CANDIDATE) {
            match Uuid::parse_str(raw.trim()) {
                Ok(id) => {
                    wanted.insert(id, id.to_string());
                }
                Err(_) => unresolved.push(raw.clone()),
            }
        }
        // Anything past the cap is unaccounted for, not merely ignored — it
        // must make the manifest incomplete like any other unresolved id.
        for extra in event_ids.iter().skip(MAX_EVIDENCE_IDS_PER_CANDIDATE) {
            unresolved.push(extra.clone());
        }

        if wanted.is_empty() {
            return Ok(ResolvedEvidence {
                events: Vec::new(),
                observed_entities: BTreeSet::new(),
                unresolved,
            });
        }

        let scope_clause = Self::scope_clause(scope);
        // The ids are bound as ONE array argument, which the driver renders as
        // `['…', '…']`. ClickHouse coerces the elements to the `UUID` column
        // type for `IN`, so this needs no `toUUID` wrapper — and the ids were
        // parsed, so the array can only ever contain canonical UUIDs.
        //
        // Single WHERE with no explicit PREWHERE (NAN-1412): an explicit
        // PREWHERE disables `optimize_move_to_prewhere`, and the id predicate is
        // the selective one we want promoted.
        let sql = format!(
            "SELECT * FROM {table} WHERE id IN ? AND {scope_clause} LIMIT {limit}",
            table = self.logs_table,
            limit = MAX_EVIDENCE_IDS_PER_CANDIDATE,
        );

        let rows = self
            .fetch_json(
                &sql,
                &[Bound::TextList(wanted.values().cloned().collect())],
            )
            .await?;
        let extractor = EntityExtractor::new();
        let observed_entities: BTreeSet<(String, String)> = extractor
            .extract_from_events(&serde_json::Value::Array(rows.clone()))
            .into_iter()
            .map(|e| (e.entity_type, e.value))
            .collect();

        let mut events = Vec::with_capacity(rows.len());
        let mut seen: BTreeSet<Uuid> = BTreeSet::new();
        for row in rows {
            let Some(id) = row
                .get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            if !seen.insert(id) {
                continue;
            }
            let timestamp = row
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(parse_ch_timestamp)
                .unwrap_or_else(Utc::now);
            let source_type = row
                .get("source_type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            let mut summary = row
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            if summary.chars().count() > SUMMARY_MAX_CHARS {
                summary = summary.chars().take(SUMMARY_MAX_CHARS).collect();
            }
            // Per-row extraction. The batch union above answers "does this
            // entity appear at all"; this answers "in which events", which is
            // what evidence and provenance must be built from.
            let entities: BTreeSet<(String, String)> = extractor
                .extract_from_events(&serde_json::Value::Array(vec![row.clone()]))
                .into_iter()
                .map(|e| (e.entity_type, e.value))
                .collect();
            events.push(ResolvedEvent {
                canonical_event_id: id.to_string(),
                timestamp,
                source_type,
                summary,
                row,
                entities,
            });
        }

        for (id, rendered) in &wanted {
            if !seen.contains(id) {
                unresolved.push(rendered.clone());
            }
        }

        Ok(ResolvedEvidence {
            events,
            observed_entities,
            unresolved,
        })
    }

    async fn had_prior_history(
        &self,
        entity_type: &str,
        entity_value: &str,
        window_start: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<bool, HuntError> {
        let Some(probe) = entity_predicate(entity_type, entity_value) else {
            // No column honestly means this entity type — report "has history"
            // so the scorer does NOT award the first-seen bonus. Failing toward
            // "unremarkable" is the safe direction: the opposite manufactures a
            // novelty finding out of an unanswerable question.
            return Ok(true);
        };
        let baseline_start = window_start - chrono::Duration::days(PRIOR_HISTORY_LOOKBACK_DAYS);
        let sql = format!(
            "SELECT count() AS n FROM (SELECT 1 FROM {table} \
             WHERE timestamp >= {from} AND timestamp < {to} AND {predicate} AND {scope} LIMIT 1)",
            table = self.logs_table,
            from = ch_instant(&baseline_start),
            to = ch_instant(&window_start),
            predicate = probe.sql,
            scope = Self::scope_clause(scope),
        );
        let rows = self.fetch_json(&sql, &probe.binds).await?;
        Ok(rows
            .first()
            .and_then(|r| r.get("n"))
            .and_then(json_u64)
            .unwrap_or(0)
            > 0)
    }

    async fn asset_prevalence(
        &self,
        entity_type: &str,
        entity_value: &str,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<Option<f64>, HuntError> {
        if window_end <= window_start {
            return Ok(None);
        }
        if (window_end - window_start) > chrono::Duration::days(MAX_PREVALENCE_WINDOW_DAYS) {
            return Ok(None);
        }
        let Some(probe) = entity_predicate(entity_type, entity_value) else {
            return Ok(None);
        };

        // Denominator: assets that produced telemetry in the window at all.
        // Numerator: those that also exhibited the entity. Both come from the
        // SAME scan, so the fraction cannot be skewed by the two halves
        // disagreeing about the window or the scope.
        //
        // The probe's placeholders are in the projection, ahead of every other
        // clause, so its binds are the whole argument list in order.
        let sql = format!(
            "SELECT uniqExact(asset) AS total, uniqExactIf(asset, hit) AS matched FROM (\
               SELECT arrayJoin(arrayFilter(x -> x != '', [src_host, dest_host])) AS asset, \
                      {predicate} AS hit \
               FROM {table} \
               WHERE timestamp >= {from} AND timestamp <= {to} AND {scope})",
            table = self.logs_table,
            from = ch_instant(&window_start),
            to = ch_instant(&window_end),
            predicate = probe.sql,
            scope = Self::scope_clause(scope),
        );
        let rows = self.fetch_json(&sql, &probe.binds).await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let total = row.get("total").and_then(json_u64).unwrap_or(0);
        let matched = row.get("matched").and_then(json_u64).unwrap_or(0);
        if total == 0 {
            // No assets in the window is not "0% prevalence", it is an
            // unanswered question. Reporting 0.0 would collect the maximum
            // rarity bonus for an entity nothing was measured against.
            return Ok(None);
        }
        Ok(Some((matched as f64 / total as f64).clamp(0.0, 1.0)))
    }

    async fn silent_source_types(
        &self,
        candidates: &[String],
        since: DateTime<Utc>,
    ) -> Result<Vec<String>, HuntError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        // `logs_per_source_5m` is the single source of truth for "events per
        // source_type over a recent window" and carries a 7-day TTL, so this is
        // a small aggregate read rather than a scan of `logs`.
        //
        // No source-scope predicate: this answers an OPERATIONAL question about
        // hunts the caller can already see, over source types those hunts
        // themselves declare in `hunt_specs.required_source_types` — a column
        // any `hunts:view` holder reads directly. It reveals nothing about event
        // CONTENT, and filtering it would report a denied source as "silent",
        // which is a false operational alarm rather than a safer answer.
        let wanted: Vec<String> = candidates
            .iter()
            .map(|c| c.trim().to_lowercase())
            .filter(|c| !c.is_empty())
            .collect();

        // `logs_per_source_5m_v2` is the PROFILE-AWARE rollup (NAN-2154). During
        // an OCSF dual-write a source appears in both lanes; summing across
        // them double-counts, which is harmless here because the only question
        // asked is "greater than zero".
        //
        // The candidate list is bound as one array. These are operator-authored
        // `hunt_specs.required_source_types` rather than report content, but
        // binding costs nothing and keeps one rule for the whole module: no
        // stored value is ever formatted into a statement.
        // The aliases are deliberately NOT `source_type` / `events`.
        //
        // A ClickHouse alias SHADOWS the column of the same name for the rest
        // of the statement, so the obvious form —
        // `sum(events) AS events … HAVING sum(events) > 0` — resolves the
        // HAVING to `sum(sum(events))` and the server rejects the whole query
        // with ILLEGAL_AGGREGATION; aliasing the group key `AS source_type`
        // breaks `GROUP BY lower(source_type)` the same way (NOT_AN_AGGREGATE).
        // That is not hypothetical: this statement errored on every call until
        // a live test ran it, and an always-erroring silence probe reports no
        // source as silent, which is the failure that makes a hunt run partial
        // against a dead source instead of being HELD.
        let sql = format!(
            "SELECT lower(source_type) AS matched_source, sum(events) AS event_count \
               FROM {rollup} \
              WHERE bucket_start >= toDateTime('{since}') \
                AND lower(source_type) IN ? \
              GROUP BY matched_source HAVING event_count > 0",
            rollup = self.tables.read("logs_per_source_5m_v2"),
            since = crate::sql_hygiene::format_ch_bound(&since),
        );
        let rows = self
            .fetch_json(&sql, &[Bound::TextList(wanted.clone())])
            .await?;
        let alive: BTreeSet<String> = rows
            .iter()
            .filter_map(|r| r.get("matched_source").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .collect();

        let mut silent: Vec<String> = wanted
            .into_iter()
            .filter(|c| !alive.contains(c))
            .collect();
        silent.sort();
        silent.dedup();
        Ok(silent)
    }
}

/// Double every `?` so the `clickhouse` crate does not read it as a parameter
/// placeholder.
///
/// The crate treats a bare `?` as a placeholder wherever it appears in the
/// template — inside a string literal included — so an interpolated value
/// carrying one makes the driver look for an argument that does not exist and
/// errors the whole probe out. That is how a lead about `https://x/a?b=1` once
/// lost its prevalence and first-seen measurements silently.
///
/// Bound arguments do NOT go through this: the driver splits the template into
/// parts before substituting and never rescans what it substituted, so a `?`
/// inside a bound value is inert. Doubling it there would corrupt the value.
/// The only caller is [`ClickHouseEvidenceResolver::scope_clause`], the one
/// fragment this module still interpolates.
fn escape_question_marks(value: &str) -> String {
    value.replace('?', "??")
}

/// ClickHouse renders `DateTime64(6,'UTC')` as `YYYY-MM-DD HH:MM:SS.ffffff` in
/// JSONEachRow — no zone suffix, and chrono will not parse it as an RFC3339
/// timestamp. Try the native form first, then RFC3339 for anything already
/// normalized upstream.
fn parse_ch_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, format) {
            return Some(naive.and_utc());
        }
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// JSONEachRow emits UInt64 as a JSON string when it exceeds 2^53, so a plain
/// `as_u64()` silently returns `None` on exactly the large counts that matter.
fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod evidence_tests;
