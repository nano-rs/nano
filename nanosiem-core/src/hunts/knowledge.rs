// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2239 — hunt knowledge: persistent, category-organised environment
//! learning, so a sweep does not re-derive the estate every night.
//!
//! # The problem
//!
//! Our own stock hunts prove it. The lolbin hunt tells the agent "a pair
//! appearing on many hosts shortly after a deployment window is a rollout —
//! rule it out". The service-account hunt's trail carries "ruled out
//! svc_backup: same nightly pattern for 90 days". Neither survives the sweep,
//! so every night the agent pays full cost to relearn the estate and may reach
//! a different conclusion from the same evidence.
//!
//! # THE LOAD-BEARING CONSTRAINT: knowledge INFORMS, it never SUPPRESSES
//!
//! A memory the agent writes is a place attacker-influenced content persists.
//! "svc_backup is benign", recorded because somebody spent two weeks making it
//! look benign, is a slow-acting blindfold — the same shape as suppression
//! gaming but worse, because nothing prompts a human to review it.
//!
//! So a knowledge row may reach a sweep's PROMPT and nothing else:
//!
//! * it is never an input to [`crate::hunts::scoring`];
//! * it never reaches `hunt_suppressions`, which stays analyst-authored;
//! * it never dismisses, hides or down-ranks a lead.
//!
//! That bounds a poisoned entry to *the agent was misled once* instead of *the
//! finding was never shown*. The invariant is not expressible in the type
//! system, so `knowledge_never_reaches_the_suppression_or_dismissal_path` in
//! `knowledge_tests.rs` asserts it by scanning both this file and the
//! suppression/scoring/service source for the coupling.
//!
//! # Three further bounds on a poisoned entry
//!
//! **Provenance, fail-closed.** A fact is prose written after reading matched
//! events — a DERIVED artifact in exactly the NAN-2137 sense. The manifest is
//! accumulated by the server from evidence that actually RESOLVED under the
//! sweep principal's own scope ([`crate::hunts::evidence::ResolvedEvidence::provenance`]),
//! never declared by the agent, and every read applies
//! [`ArtifactScope::sql_predicate`] so a fact learned from a source a reader
//! cannot see is not visible to them.
//!
//! **Decay.** `expires_at` is NOT NULL: nothing here is permanent. Recording
//! the same `(category, subject, fact)` again reconfirms the existing row and
//! pushes its expiry out rather than duplicating it, so a fact that stops being
//! true stops being recalled on its own.
//!
//! **Revocation that sticks.** `uq_hunt_knowledge_identity` is UNCONDITIONAL,
//! so a revoked row permanently occupies its identity slot and
//! [`KnowledgeRepository::record`]'s `WHERE revoked_at IS NULL` guard cannot
//! resurrect it. A later sweep that tries is refused and counted — see
//! [`RecordOutcome::RefusedRevoked`].
//!
//! # Why this is its own repository
//!
//! [`crate::hunts::repository::HuntRepository`] is where suppression and lead
//! dismissal live. Keeping knowledge out of that file is not tidiness: it is
//! what makes the guard test above a cheap file-level scan rather than a
//! call-graph analysis, and it means the type that can record a memory has no
//! method that can hide a finding.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{ArtifactScope, SourceProvenance};
use crate::hunts::error::HuntError;
use crate::typeid;

// =============================================================================
// Bounds
// =============================================================================
//
// Each mirrors a CHECK in migration 9000061. Enforced here as well as there so
// a caller gets a comprehensible 400 rather than a constraint-violation 500,
// and so the bound survives a future write path that skips this module.

/// Matches `hunt_knowledge_category_normalized`.
pub const MAX_CATEGORY_CHARS: usize = 64;
/// Matches `hunt_knowledge_subject_normalized`.
pub const MAX_SUBJECT_CHARS: usize = 512;
/// Matches `hunt_knowledge_fact_bounded`.
pub const MAX_FACT_CHARS: usize = 4096;
/// Matches `hunt_knowledge_evidence_bounded`.
pub const MAX_EVIDENCE_REFS: usize = 50;
/// Matches `hunt_knowledge_revoke_reason_bounded`.
pub const MAX_REVOKE_REASON_CHARS: usize = 1024;
/// Ceiling on the per-category rollup returned alongside a listing.
///
/// Category cardinality is agent-controlled — the taxonomy is deliberately
/// open — so the rollup needs a bound that the row limit does not give it.
pub const MAX_CATEGORY_ROLLUP: usize = 200;

/// Reject a non-finite confidence rather than pass it to the database.
///
/// `f64::clamp` returns NaN for a NaN input, and NaN survives the cast to
/// `numeric` — where it compares as GREATER than every real value, so
/// `hunt_knowledge_confidence_range` rejects it and the caller gets a 500 from
/// a constraint violation instead of a 400 from a malformed field. JSON has no
/// NaN literal, so this is unreachable today; it is here so it stays
/// unreachable when the next caller is not JSON.
pub fn sanitize_confidence(raw: Option<f64>) -> Result<f64, HuntError> {
    let value = raw.unwrap_or(0.5);
    if value.is_nan() {
        return Err(HuntError::Validation(
            "confidence must be a number between 0 and 1".to_string(),
        ));
    }
    // Infinities clamp correctly, so only NaN needs rejecting.
    Ok(value.clamp(0.0, 1.0))
}

/// Default lifetime of a newly learned fact.
///
/// Chosen against the cadence this feature exists to serve: a nightly hunt
/// re-observes a still-true fact roughly thirty times before it would lapse, so
/// decay costs nothing while the fact holds and removes it promptly once it
/// stops.
pub const DEFAULT_TTL_DAYS: i64 = 30;
/// Ceiling on a caller-requested lifetime.
///
/// The agent picks its own TTL, so this is what stops "permanent" being
/// expressible by asking for ten thousand days. Decay is one of the three
/// bounds on a poisoned entry; an unbounded TTL removes it.
pub const MAX_TTL_DAYS: i64 = 90;

/// Every column of `hunt_knowledge`, aliased `k`.
///
/// `fact_digest` is GENERATED, so it is read and never written — the database
/// owns fact identity. See the migration for why that matters to revocation.
const KNOWLEDGE_SELECT: &str = "SELECT k.id, k.category, k.subject, k.fact, k.fact_digest, \
     k.confidence::float8 AS confidence, k.learned_by_sweep_id, k.confirmed_by_sweep_id, \
     k.evidence_event_ids, k.observation_count, k.relearn_attempts, k.last_relearn_attempt_at, \
     k.learned_at, k.confirmed_at, k.expires_at, k.revoked_at, k.revoked_by, k.revoke_reason, \
     k.source_types, k.source_types_complete \
       FROM hunt_knowledge k";

// =============================================================================
// Wire types
// =============================================================================

/// One learned fact about the environment.
///
/// The provenance pair is exposed rather than stripped at the repository
/// boundary, for the reason [`crate::hunts::models`] documents: a reviewer
/// looking at a response body can see whether the fact is attributed at all.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntKnowledge {
    #[serde(with = "typeid::hunt_knowledge")]
    #[schema(value_type = String)]
    pub id: Uuid,

    /// Agent-chosen and normalized: `account`, `app`, `app_endpoint`, whatever
    /// the estate warrants. There is deliberately no fixed taxonomy.
    pub category: String,
    /// The entity or thing the fact is about, lowercased for stable grouping.
    pub subject: String,
    /// The learned statement. Untrusted attacker-influenceable prose — render
    /// it inert, exactly like a lead narrative.
    pub fact: String,
    /// Database-computed identity of the normalized fact. Exposed so a client
    /// can tell "reconfirmed the fact I sent" from "matched a near-duplicate".
    pub fact_digest: String,

    /// The agent's own claim, clamped to `0.0..=1.0`. Weigh `observation_count`
    /// alongside it: that one is server-counted, this one is not.
    pub confidence: f64,

    #[serde(default, with = "typeid::hunt_sweep::opt")]
    #[schema(value_type = Option<String>)]
    pub learned_by_sweep_id: Option<Uuid>,
    #[serde(default, with = "typeid::hunt_sweep::opt")]
    #[schema(value_type = Option<String>)]
    pub confirmed_by_sweep_id: Option<Uuid>,

    /// Canonical ClickHouse event ids the fact was learned from. Pointers, not
    /// bodies: the log store stays the system of record.
    pub evidence_event_ids: Vec<String>,

    /// Recordings by a sweep other than the one that last confirmed it.
    /// Repeating a fact inside one sweep does not inflate it.
    pub observation_count: i32,
    /// Times a sweep tried to re-learn this fact AFTER an analyst revoked it.
    /// Non-zero on a tombstone is worth reading: either the revocation was
    /// wrong, or something keeps pushing the same narrative at the agent.
    pub relearn_attempts: i32,
    pub last_relearn_attempt_at: Option<DateTime<Utc>>,

    pub learned_at: DateTime<Utc>,
    pub confirmed_at: DateTime<Utc>,
    /// Never null. Expired knowledge is not recalled.
    pub expires_at: DateTime<Utc>,

    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub revoked_by: Option<Uuid>,
    pub revoke_reason: Option<String>,

    pub source_types: Vec<String>,
    pub source_types_complete: bool,
}

/// Record a fact. Reachable by a sweep key (`hunts:report`) and by nothing else.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RecordKnowledgeRequest {
    /// Free-form and agent-chosen. Normalized to `[a-z0-9_-]{1,64}`: spaces
    /// become underscores, case is folded. Anything left outside that charset
    /// is rejected rather than mangled, because a "category" that is really a
    /// paragraph of injected prose must not become a UI grouping header.
    pub category: String,
    /// The entity or thing the fact is about. Trimmed and lowercased.
    pub subject: String,
    /// The learned statement. Whitespace runs — including newlines — collapse
    /// to single spaces: a fact is one statement, and the collapsed form denies
    /// a multi-line payload the framing it would need in a recalled prompt.
    pub fact: String,
    /// `0.0..=1.0`, clamped. Optional; defaults to 0.5.
    #[serde(default)]
    pub confidence: Option<f64>,
    /// The sweep learning this. Must currently hold an unexpired lease — see
    /// [`KnowledgeRepository::record`].
    pub sweep_id: String,
    /// Canonical event ids the fact was learned from. The server resolves these
    /// under this principal's own source scope and stamps the manifest from
    /// what came back; an empty or partly unresolvable list produces an
    /// INCOMPLETE manifest, which fails closed for every source-scoped reader.
    #[serde(default)]
    pub evidence_event_ids: Vec<String>,
    /// Requested lifetime, clamped to `1..=`[`MAX_TTL_DAYS`]. Defaults to
    /// [`DEFAULT_TTL_DAYS`].
    #[serde(default)]
    pub ttl_days: Option<i64>,
}

/// What a recording did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordOutcome {
    /// First time this `(category, subject, fact)` has been seen.
    Learned,
    /// It already existed and is now confirmed again, with its expiry pushed
    /// out. This is the common case for a true fact under a nightly hunt.
    Reconfirmed,
    /// An analyst REVOKED this fact and the recording was refused.
    ///
    /// Reported rather than swallowed so a sweep can stop re-deriving something
    /// a human has already rejected — and so the tool calling this can say so
    /// in its trail instead of silently believing it wrote a memory.
    RefusedRevoked,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecordKnowledgeResponse {
    pub outcome: RecordOutcome,
    /// The stored row. For [`RecordOutcome::RefusedRevoked`] this is the
    /// TOMBSTONE — including who revoked it and why — so the agent learns the
    /// human's reason rather than merely that it failed.
    pub knowledge: HuntKnowledge,
}

/// Revoke a fact. Analyst-only (`hunts:triage`).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RevokeKnowledgeRequest {
    /// Required. A revocation is permanent, and "why" is the only thing that
    /// tells the next analyst whether to trust the one before them.
    pub reason: String,
}

/// One category and how much live knowledge sits under it.
///
/// Counted under the caller's own artifact scope, in the same statement shape
/// as the listing: a count that included facts the caller cannot read would be
/// an oracle for their existence.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct KnowledgeCategoryCount {
    pub category: String,
    pub count: i64,
}

/// Filters for a listing.
#[derive(Debug, Clone, Default)]
pub struct ListKnowledgeQuery {
    pub category: Option<String>,
    pub subject: Option<String>,
    pub min_confidence: Option<f64>,
    /// Include analyst-revoked tombstones. Off by default: the DEFAULT of this
    /// endpoint is the recall contract a sweep consumes.
    pub include_revoked: bool,
    /// Include lapsed knowledge. Off by default — expired knowledge is not
    /// recalled.
    pub include_expired: bool,
    pub limit: i64,
    pub offset: i64,
}

// =============================================================================
// Normalization
// =============================================================================

/// Normalize an agent-chosen category into the form the database will accept.
///
/// Enforcing the normalized form in SQL as well (`hunt_knowledge_category_normalized`)
/// is what stops a second write path from creating `Account` alongside
/// `account` — two rail entries that look identical and group nothing.
pub fn normalize_category(raw: &str) -> Result<String, HuntError> {
    let lowered = raw.trim().to_lowercase();
    if lowered.is_empty() {
        return Err(HuntError::Validation("category is required".to_string()));
    }
    // Spaces become underscores so "App Endpoint" is a usable category rather
    // than a rejection. Everything else outside the charset is REJECTED, not
    // stripped: silently deleting characters would map two distinct categories
    // onto one identity.
    let normalized: String = lowered
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_");
    if normalized.chars().count() > MAX_CATEGORY_CHARS {
        return Err(HuntError::Validation(format!(
            "category is longer than {MAX_CATEGORY_CHARS} characters"
        )));
    }
    let shaped = normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && normalized
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !shaped {
        return Err(HuntError::Validation(format!(
            "category must be {MAX_CATEGORY_CHARS} characters or fewer of a-z, 0-9, _ or -, \
             starting with a letter or digit (got {normalized:?})"
        )));
    }
    Ok(normalized)
}

/// Trim and lowercase a subject, matching `hunt_knowledge_subject_normalized`.
pub fn normalize_subject(raw: &str) -> Result<String, HuntError> {
    let normalized = raw.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(HuntError::Validation("subject is required".to_string()));
    }
    if normalized.chars().count() > MAX_SUBJECT_CHARS {
        return Err(HuntError::Validation(format!(
            "subject is longer than {MAX_SUBJECT_CHARS} characters"
        )));
    }
    Ok(normalized)
}

/// Collapse a fact to a single line and bound it.
///
/// Rejected rather than truncated when over-long: truncating prose changes what
/// it asserts, and a half-sentence memory recalled as fact is worse than no
/// memory. A knowledge recording is one small call, so a 400 costs the sweep a
/// retry rather than its whole run.
pub fn normalize_fact(raw: &str) -> Result<String, HuntError> {
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err(HuntError::Validation("fact is required".to_string()));
    }
    if normalized.chars().count() > MAX_FACT_CHARS {
        return Err(HuntError::Validation(format!(
            "fact is longer than {MAX_FACT_CHARS} characters"
        )));
    }
    Ok(normalized)
}

/// Clamp a requested lifetime into `1..=`[`MAX_TTL_DAYS`].
pub fn clamp_ttl_days(requested: Option<i64>) -> i64 {
    requested.unwrap_or(DEFAULT_TTL_DAYS).clamp(1, MAX_TTL_DAYS)
}

/// Deduplicate and cap evidence pointers.
///
/// Truncated rather than rejected, unlike the fact: dropping surplus pointers
/// costs corroboration detail but does not change what the fact asserts.
pub fn normalize_evidence_refs(raw: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    raw.iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert(id.to_string()))
        .take(MAX_EVIDENCE_REFS)
        .map(str::to_string)
        .collect()
}

// =============================================================================
// SQL construction
// =============================================================================

/// Build the listing statement and say whether a scope parameter is bound.
///
/// Split out so the predicate can be asserted without a database — a dropped
/// provenance filter is invisible in review and expensive to notice in
/// production.
pub(crate) fn build_list_sql(query: &ListKnowledgeQuery, scope: &ArtifactScope) -> (String, bool) {
    let mut sql = format!("{KNOWLEDGE_SELECT} WHERE 1 = 1");
    let mut param = 1usize;
    if !query.include_revoked {
        sql.push_str(" AND k.revoked_at IS NULL");
    }
    if !query.include_expired {
        sql.push_str(" AND k.expires_at > NOW()");
    }
    if query.category.is_some() {
        sql.push_str(&format!(" AND k.category = ${param}"));
        param += 1;
    }
    if query.subject.is_some() {
        sql.push_str(&format!(" AND k.subject = ${param}"));
        param += 1;
    }
    if query.min_confidence.is_some() {
        sql.push_str(&format!(" AND k.confidence >= ${param}::float8::numeric"));
        param += 1;
    }
    let scoped = !scope.is_unrestricted();
    if scoped {
        // In the WHERE clause, so denied rows are excluded BEFORE LIMIT/OFFSET.
        // A post-fetch filter would still page over them and leave the page
        // size as an oracle for how many exist.
        sql.push_str(&ArtifactScope::sql_predicate(
            "k.source_types",
            "k.source_types_complete",
            param,
        ));
        param += 1;
    }
    // Ordered for grouping, not for ranking: category then subject, so a caller
    // can render sections by walking the list once. Confidence and recency
    // break ties WITHIN a subject, which is the only place ordering by them
    // means anything.
    sql.push_str(&format!(
        " ORDER BY k.category ASC, k.subject ASC, k.confidence DESC, k.confirmed_at DESC \
          LIMIT ${} OFFSET ${}",
        param,
        param + 1
    ));
    (sql, scoped)
}

/// Build the per-category rollup.
///
/// Deliberately the same predicate set as [`build_list_sql`] minus paging: a
/// count computed under different visibility rules than the rows it summarizes
/// would report knowledge the caller cannot read.
pub(crate) fn build_category_counts_sql(
    query: &ListKnowledgeQuery,
    scope: &ArtifactScope,
) -> (String, bool) {
    let mut sql = String::from("SELECT k.category, COUNT(*)::bigint AS count FROM hunt_knowledge k WHERE 1 = 1");
    let mut param = 1usize;
    if !query.include_revoked {
        sql.push_str(" AND k.revoked_at IS NULL");
    }
    if !query.include_expired {
        sql.push_str(" AND k.expires_at > NOW()");
    }
    let scoped = !scope.is_unrestricted();
    if scoped {
        sql.push_str(&ArtifactScope::sql_predicate(
            "k.source_types",
            "k.source_types_complete",
            param,
        ));
        param += 1;
    }
    let _ = param;
    // Bounded, and ordered by SIZE rather than alphabetically.
    //
    // Categories are agent-chosen, so their cardinality is agent-controlled: an
    // estate that accumulates ten thousand one-off categories would otherwise
    // return all of them on every recall. Truncating by count drops the long
    // tail of singletons; truncating alphabetically would drop everything after
    // the letter it ran out on, which is a far worse thing to do silently.
    // `category ASC` only breaks ties, so the result stays deterministic.
    sql.push_str(&format!(
        " GROUP BY k.category ORDER BY count DESC, k.category ASC LIMIT {MAX_CATEGORY_ROLLUP}"
    ));
    (sql, scoped)
}

/// Build the revocation statement and say whether a scope parameter is bound.
///
/// Scoped like a read, not like a write, because it RETURNS the row: an
/// unscoped `UPDATE … RETURNING` would hand a restricted caller the contents of
/// a fact learned from a source they are denied — through a mutation rather
/// than a SELECT, which is exactly the site a read-focused audit walks past.
pub(crate) fn build_revoke_sql(scope: &ArtifactScope) -> (String, bool) {
    let mut sql = String::from(
        "UPDATE hunt_knowledge k \
            SET revoked_at = NOW(), revoked_by = $2, revoke_reason = $3 \
          WHERE k.id = $1 AND k.revoked_at IS NULL",
    );
    let scoped = !scope.is_unrestricted();
    if scoped {
        sql.push_str(&ArtifactScope::sql_predicate(
            "k.source_types",
            "k.source_types_complete",
            4,
        ));
    }
    sql.push_str(
        " RETURNING k.id, k.category, k.subject, k.fact, k.fact_digest, \
           k.confidence::float8 AS confidence, k.learned_by_sweep_id, \
           k.confirmed_by_sweep_id, k.evidence_event_ids, k.observation_count, \
           k.relearn_attempts, k.last_relearn_attempt_at, k.learned_at, k.confirmed_at, \
           k.expires_at, k.revoked_at, k.revoked_by, k.revoke_reason, \
           k.source_types, k.source_types_complete",
    );
    (sql, scoped)
}

// =============================================================================
// Repository
// =============================================================================

/// Postgres access for `hunt_knowledge`.
///
/// Separate from [`crate::hunts::repository::HuntRepository`] on purpose. That
/// type owns lead dismissal and the single suppression insert; this one owns
/// memory. Keeping them apart means the object that can record a memory has no
/// method that can hide a finding, and it keeps the guard test a file scan.
#[derive(Clone)]
pub struct KnowledgeRepository {
    pool: PgPool,
}

impl KnowledgeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a fact, or reconfirm one that already exists.
    ///
    /// # The sweep must be live
    ///
    /// The named sweep has to be `leased` or `running` with an unexpired lease.
    /// Without that, a `hunts:report` key could attribute memory to any sweep
    /// at any time, including finished ones — and "learned during sweep X" is
    /// the only thing tying a fact back to reviewable work. The practical
    /// consequence for a tool author is an ORDERING requirement: record
    /// knowledge DURING the sweep, before submitting the report that finishes
    /// it. The error text says so.
    ///
    /// # The upsert, and the tombstone
    ///
    /// The statement conflicts on `(category, subject, fact_digest)` — the
    /// UNCONDITIONAL unique index — and its `WHERE hunt_knowledge.revoked_at IS
    /// NULL` guard means a conflict onto a revoked row updates nothing and
    /// returns nothing. That is the whole mechanism by which an analyst's
    /// revocation sticks: the tombstone permanently occupies the identity, so
    /// there is no free slot for a later sweep to insert a fresh live row into.
    ///
    /// When that happens we count the attempt on the tombstone and hand it back
    /// as [`RecordOutcome::RefusedRevoked`].
    ///
    /// `observation_count == 1` distinguishes a fresh insert from a
    /// reconfirmation without the `xmax = 0` trick: the identity row is unique
    /// forever, so only an insert can leave the counter at its default.
    pub async fn record(
        &self,
        category: &str,
        subject: &str,
        fact: &str,
        confidence: f64,
        sweep_id: Uuid,
        evidence_event_ids: &[String],
        ttl_days: i64,
        provenance: &SourceProvenance,
    ) -> Result<(RecordOutcome, HuntKnowledge), HuntError> {
        let (source_types, complete) = provenance.clone().into_parts();
        let expires_at = Utc::now() + Duration::days(ttl_days);

        let mut tx = self.pool.begin().await?;

        // Reassert the sweep is live. `FOR SHARE` rather than `FOR UPDATE`:
        // several facts from one sweep may land concurrently and none of them
        // mutate the sweep row, but the lock still serializes against a
        // reassignment committing underneath us.
        let live = sqlx::query(
            "SELECT id FROM hunt_sweeps \
              WHERE id = $1 AND status IN ('leased', 'running') \
                AND lease_expires_at IS NOT NULL AND lease_expires_at > NOW() \
              FOR SHARE",
        )
        .bind(sweep_id)
        .fetch_optional(&mut *tx)
        .await?;
        if live.is_none() {
            tx.rollback().await?;
            return Err(HuntError::Conflict(format!(
                "sweep {sweep_id} is not currently running with a valid lease; record knowledge \
                 during the sweep, before submitting its report"
            )));
        }

        let recorded = sqlx::query(
            r#"INSERT INTO hunt_knowledge
                 (category, subject, fact, confidence, learned_by_sweep_id,
                  confirmed_by_sweep_id, evidence_event_ids, expires_at,
                  source_types, source_types_complete)
               VALUES ($1, $2, $3, $4::float8::numeric, $5, $5, $6, $7, $8, $9)
               ON CONFLICT (category, subject, fact_digest) DO UPDATE
                  SET confirmed_at = NOW(),
                      -- GREATEST, so a short-TTL recording can never SHORTEN
                      -- the life of a fact another sweep vouched for longer.
                      expires_at = GREATEST(hunt_knowledge.expires_at, EXCLUDED.expires_at),
                      -- Latest claim wins, and deliberately does not accumulate.
                      -- If repetition raised confidence, an adversary who can
                      -- make a sweep re-record a fact could reach 1.0 by
                      -- patience alone.
                      confidence = EXCLUDED.confidence,
                      confirmed_by_sweep_id = EXCLUDED.confirmed_by_sweep_id,
                      evidence_event_ids = ARRAY(
                          SELECT DISTINCT e
                            FROM unnest(hunt_knowledge.evidence_event_ids
                                        || EXCLUDED.evidence_event_ids) e
                           LIMIT 50
                      ),
                      -- Only a DIFFERENT sweep counts, so repeating a fact
                      -- inside one run cannot manufacture corroboration.
                      observation_count = hunt_knowledge.observation_count
                          + CASE WHEN EXCLUDED.confirmed_by_sweep_id
                                      IS DISTINCT FROM hunt_knowledge.confirmed_by_sweep_id
                                 THEN 1 ELSE 0 END,
                      source_types = ARRAY(
                          SELECT DISTINCT s
                            FROM unnest(hunt_knowledge.source_types
                                        || EXCLUDED.source_types) s
                      ),
                      -- Monotonic toward failure, matching SourceProvenance::merge:
                      -- one incomplete contributor makes the union incomplete,
                      -- and merging good data can never launder it back.
                      source_types_complete = hunt_knowledge.source_types_complete
                          AND EXCLUDED.source_types_complete
                WHERE hunt_knowledge.revoked_at IS NULL
               RETURNING id, category, subject, fact, fact_digest,
                         confidence::float8 AS confidence, learned_by_sweep_id,
                         confirmed_by_sweep_id, evidence_event_ids, observation_count,
                         relearn_attempts, last_relearn_attempt_at, learned_at,
                         confirmed_at, expires_at, revoked_at, revoked_by, revoke_reason,
                         source_types, source_types_complete"#,
        )
        .bind(category)
        .bind(subject)
        .bind(fact)
        .bind(confidence)
        .bind(sweep_id)
        .bind(evidence_event_ids)
        .bind(expires_at)
        .bind(&source_types)
        .bind(complete)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = recorded {
            let knowledge = knowledge_from_row(&row)?;
            let outcome = if knowledge.observation_count == 1 {
                RecordOutcome::Learned
            } else {
                RecordOutcome::Reconfirmed
            };
            tx.commit().await?;
            return Ok((outcome, knowledge));
        }

        // Nothing came back, so the conflict landed on a tombstone. Count the
        // attempt: silence here would let a sweep re-derive a rejected fact
        // every night with nothing to show an analyst that it was happening.
        //
        // The digest is recomputed by the SAME database function the generated
        // column uses, so this cannot drift from the row it means to find.
        let tombstone = sqlx::query(
            r#"UPDATE hunt_knowledge
                  SET relearn_attempts = relearn_attempts + 1,
                      last_relearn_attempt_at = NOW()
                WHERE category = $1 AND subject = $2
                  AND fact_digest = hunt_knowledge_fact_digest($3)
                  AND revoked_at IS NOT NULL
               RETURNING id, category, subject, fact, fact_digest,
                         confidence::float8 AS confidence, learned_by_sweep_id,
                         confirmed_by_sweep_id, evidence_event_ids, observation_count,
                         relearn_attempts, last_relearn_attempt_at, learned_at,
                         confirmed_at, expires_at, revoked_at, revoked_by, revoke_reason,
                         source_types, source_types_complete"#,
        )
        .bind(category)
        .bind(subject)
        .bind(fact)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = tombstone else {
            // The upsert matched nothing and there is no tombstone either, so
            // the row vanished between the two statements. Rolling back and
            // reporting a conflict is honest; inventing an outcome is not.
            tx.rollback().await?;
            return Err(HuntError::Conflict(
                "knowledge row changed during recording; retry".to_string(),
            ));
        };
        let knowledge = knowledge_from_row(&row)?;
        tx.commit().await?;
        Ok((RecordOutcome::RefusedRevoked, knowledge))
    }

    /// List knowledge under the caller's artifact scope.
    pub async fn list(
        &self,
        query: &ListKnowledgeQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntKnowledge>, HuntError> {
        let (sql, scoped) = build_list_sql(query, scope);
        let mut q = sqlx::query(&sql);
        if let Some(category) = &query.category {
            q = q.bind(category.clone());
        }
        if let Some(subject) = &query.subject {
            q = q.bind(subject.clone());
        }
        if let Some(min) = query.min_confidence {
            q = q.bind(min);
        }
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let rows = q
            .bind(query.limit)
            .bind(query.offset)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(knowledge_from_row).collect()
    }

    /// Per-category counts under the same visibility rules as [`Self::list`].
    pub async fn category_counts(
        &self,
        query: &ListKnowledgeQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<KnowledgeCategoryCount>, HuntError> {
        let (sql, scoped) = build_category_counts_sql(query, scope);
        let mut q = sqlx::query(&sql);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                Ok(KnowledgeCategoryCount {
                    category: row.try_get("category")?,
                    count: row.try_get("count")?,
                })
            })
            .collect()
    }

    /// Revoke a fact. Returns `None` when it does not exist, is already
    /// revoked, or is not visible under this caller's source scope.
    ///
    /// Those three are one answer on purpose: distinguishing them would tell a
    /// caller that a fact they may not read exists.
    ///
    /// The revocation is terminal. There is no un-revoke, because the value of
    /// the guarantee is that a sweep cannot undo it — and an analyst-facing
    /// un-revoke is one API call away from being the thing an agent's key gets
    /// pointed at next.
    pub async fn revoke(
        &self,
        id: Uuid,
        reason: &str,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<Option<HuntKnowledge>, HuntError> {
        let (sql, scoped) = build_revoke_sql(scope);
        let mut q = sqlx::query(&sql).bind(id).bind(actor).bind(reason);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let row = q.fetch_optional(&self.pool).await?;
        row.as_ref().map(knowledge_from_row).transpose()
    }
}

fn knowledge_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntKnowledge, HuntError> {
    Ok(HuntKnowledge {
        id: row.try_get("id")?,
        category: row.try_get("category")?,
        subject: row.try_get("subject")?,
        fact: row.try_get("fact")?,
        fact_digest: row.try_get("fact_digest")?,
        confidence: row.try_get("confidence")?,
        learned_by_sweep_id: row.try_get("learned_by_sweep_id")?,
        confirmed_by_sweep_id: row.try_get("confirmed_by_sweep_id")?,
        evidence_event_ids: row.try_get("evidence_event_ids")?,
        observation_count: row.try_get("observation_count")?,
        relearn_attempts: row.try_get("relearn_attempts")?,
        last_relearn_attempt_at: row.try_get("last_relearn_attempt_at")?,
        learned_at: row.try_get("learned_at")?,
        confirmed_at: row.try_get("confirmed_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        revoked_by: row.try_get("revoked_by")?,
        revoke_reason: row.try_get("revoke_reason")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
    })
}

#[cfg(test)]
#[path = "knowledge_tests.rs"]
mod knowledge_tests;
