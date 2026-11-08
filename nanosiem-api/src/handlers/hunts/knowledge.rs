// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2239 — hunt knowledge: recall, record, revoke.
//!
//! # The permission split, and why it is not new permissions
//!
//! * `hunts:view` — recall and the analyst review list.
//! * `hunts:report` — record. The ONE write scope an unattended sweep key
//!   carries, held by no human role (migration 9000054), so knowledge is
//!   agent-authored by construction.
//! * `hunts:triage` — revoke. The same authority that dismisses a lead, for the
//!   same reason: rejecting something an agent concluded is analyst work.
//!
//! A separate `hunts:knowledge` permission would have to be granted to every
//! existing role before it was usable, and would let a tenant hold the two
//! halves apart in a way with no security meaning — anyone who can suppress a
//! finding can already do strictly more damage than anyone who can revoke a
//! memory.
//!
//! # Knowledge INFORMS, it never SUPPRESSES
//!
//! Nothing here dismisses a lead, writes a suppression, or feeds a score. A
//! sweep RECALLS through `GET /api/hunts/knowledge` before it starts looking and
//! puts what it gets in its own prompt; that is the entire coupling, and it is
//! why a poisoned memory costs the agent one misleading rather than costing the
//! analyst a finding they never saw. `hunt_knowledge_stays_out_of_the_triage_path`
//! below is the regression guard for this file; its counterpart in
//! `nanosiem-core/src/hunts/knowledge_tests.rs` guards the repository layer.
//!
//! # Provenance
//!
//! Recording resolves the cited events under the SWEEP PRINCIPAL's own live-data
//! scope and stamps the manifest from what came back — an agent never declares
//! its own provenance. Every read passes the caller's [`ArtifactScope`] down to
//! SQL, so a fact learned from a source a reader is denied is not visible to
//! them. Nothing is filtered in the handler: a post-fetch filter still pages
//! over denied rows, which leaves the page size as an oracle for how many exist.

use std::str::FromStr;

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, HUNT_KNOWLEDGE_REVOKED};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{
    clamp_ttl_days, normalize_category, normalize_evidence_refs, normalize_fact, normalize_subject,
    EvidenceResolver, HuntKnowledge, KnowledgeCategoryCount, KnowledgeRepository, ListKnowledgeQuery,
    sanitize_confidence, RecordKnowledgeRequest, RecordKnowledgeResponse, RevokeKnowledgeRequest,
    MAX_REVOKE_REASON_CHARS,
};
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::ClientContext;
use serde::{Deserialize, Serialize};

use super::types::page_size;
use super::artifact_scope;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Build the knowledge repository for one request.
///
/// Deliberately NOT reached through `super::service`. `HuntService` owns lead
/// dismissal and the suppression write; keeping knowledge on its own repository
/// means the object this handler holds has no method that can hide a finding.
fn repository(state: &AppState) -> KnowledgeRepository {
    KnowledgeRepository::new(state.pool.clone())
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListKnowledgeParams {
    /// Exact category, already normalized (`account`, `app_endpoint`, …).
    /// Normalized again server-side so a caller sending `Account` still matches.
    #[serde(default)]
    pub category: Option<String>,
    /// Exact subject. Lowercased server-side.
    #[serde(default)]
    pub subject: Option<String>,
    /// Floor on the agent's claimed confidence.
    #[serde(default)]
    pub min_confidence: Option<f64>,
    /// Include analyst-revoked tombstones. Off by default — the default of this
    /// endpoint IS the recall contract a sweep consumes.
    #[serde(default)]
    pub include_revoked: bool,
    /// Include lapsed knowledge. Off by default: expired knowledge is not
    /// recalled.
    #[serde(default)]
    pub include_expired: bool,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Knowledge plus the per-category rollup that makes it groupable.
///
/// The rollup is computed under the caller's own scope in the same statement
/// shape as the rows, so it can never report knowledge the caller cannot read.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListKnowledgeResponse {
    /// Ordered by category, then subject — walk once to render sections.
    pub knowledge: Vec<HuntKnowledge>,
    /// Every category with live knowledge in it, and how much. Reflects the
    /// whole store under the caller's scope, NOT just the current page.
    pub categories: Vec<KnowledgeCategoryCount>,
}

/// List what the hunter knows about this environment
///
/// The recall surface. A sweep calls this before it starts looking so it does
/// not re-derive the estate: "a lolbin pair appearing on many hosts shortly
/// after a deployment window is a rollout", "svc_backup has run the same nightly
/// pattern for 90 days".
///
/// # This informs a sweep; it does not suppress anything
///
/// Recalled knowledge belongs in the agent's prompt and nowhere else. It must
/// not auto-dismiss a lead or feed the suppression path — suppression stays
/// analyst-only. That is what bounds a poisoned memory to "the agent was misled
/// once" rather than "the finding was never shown".
///
/// # Defaults are the recall contract
///
/// Revoked and expired knowledge is excluded unless asked for. `include_revoked`
/// is for the analyst review screen, where a tombstone's `relearn_attempts` is
/// the interesting number: a fact a sweep keeps trying to re-learn after a human
/// rejected it is either a wrong revocation or something pushing a narrative.
#[utoipa::path(
    get,
    path = "/api/hunts/knowledge",
    tag = "hunts",
    params(ListKnowledgeParams),
    responses(
        (status = 200, description = "Knowledge retrieved, ordered for grouping", body = ListKnowledgeResponse),
        (status = 400, description = "Invalid filter"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_knowledge(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListKnowledgeParams>,
) -> Result<Json<ListKnowledgeResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;

    // Normalized rather than passed through, so `?category=Account` matches the
    // stored `account` instead of silently returning nothing. A filter that
    // reads as "there is no such knowledge" when it means "you spelled it with
    // a capital" is the worst failure mode for a recall surface.
    let category = params
        .category
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_category)
        .transpose()?;
    let subject = params
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_subject)
        .transpose()?;

    let query = ListKnowledgeQuery {
        category,
        subject,
        // A non-finite floor is dropped rather than passed down: bound as
        // `numeric` NaN it compares GREATER than every stored confidence, so the
        // filter would return an empty page that reads as "we know nothing"
        // rather than as "your filter was malformed".
        min_confidence: params.min_confidence.filter(|value| value.is_finite()),
        include_revoked: params.include_revoked,
        include_expired: params.include_expired,
        limit: page_size(params.limit),
        offset: params.offset.unwrap_or(0).max(0),
    };

    let scope = artifact_scope(&auth);
    let repo = repository(&state);
    let knowledge = repo.list(&query, &scope).await?;
    let categories = repo.category_counts(&query, &scope).await?;
    Ok(Json(ListKnowledgeResponse {
        knowledge,
        categories,
    }))
}

/// Record something the hunter learned
///
/// Reachable by a sweep's key — `hunts:report` — and by no human role.
///
/// # Ordering matters
///
/// The named sweep must currently be `leased` or `running` with an unexpired
/// lease, so knowledge is recorded DURING the sweep, before the report that
/// finishes it. Without that, a report key could attribute memory to any sweep
/// at any time and "learned during sweep X" would be decoration. A `409` means
/// the sweep is not live.
///
/// # Recording the same thing again is not a duplicate
///
/// A matching `(category, subject, fact)` reconfirms the existing row and pushes
/// its expiry out — that is how a true fact survives while a stale one decays.
/// The response says which happened: `learned`, `reconfirmed`, or
/// `refused_revoked`.
///
/// # `refused_revoked` is not an error
///
/// It means an analyst REVOKED this fact and the recording was refused. The
/// tombstone comes back with their reason so the sweep can stop re-deriving it.
/// A revocation is permanent by design: a later sweep must not be able to
/// silently re-learn something a human rejected.
///
/// # Provenance
///
/// `evidence_event_ids` are resolved under THIS principal's own source scope and
/// the manifest is stamped from what came back. An empty list, or one with ids
/// that resolve to nothing readable, produces an INCOMPLETE manifest — which
/// fails closed for every source-scoped reader. The agent never declares its own
/// provenance.
#[utoipa::path(
    post,
    path = "/api/hunts/knowledge",
    tag = "hunts",
    request_body = RecordKnowledgeRequest,
    responses(
        (status = 200, description = "Learned, reconfirmed, or refused because an analyst revoked it", body = RecordKnowledgeResponse),
        (status = 400, description = "Invalid category, subject, fact or sweep id"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "The named sweep is not running with a valid lease — record during the sweep, before reporting"),
    ),
    security(("api_key" = []))
)]
pub async fn record_knowledge(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<RecordKnowledgeRequest>,
) -> Result<Json<RecordKnowledgeResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_REPORT)?;

    let category = normalize_category(&req.category)?;
    let subject = normalize_subject(&req.subject)?;
    let fact = normalize_fact(&req.fact)?;
    // Clamped rather than rejected: an out-of-range confidence is a malformed
    // claim about a fact, not a malformed fact. NaN is the exception — it is not
    // a claim at all, and it would reach the CHECK as a 500 instead of a 400.
    let confidence = sanitize_confidence(req.confidence)?;
    let ttl_days = clamp_ttl_days(req.ttl_days);
    let evidence_event_ids = normalize_evidence_refs(&req.evidence_event_ids);

    let sweep_id = TypeIdParam::from_str(req.sweep_id.trim())
        .map_err(|e| ApiError::BadRequest(format!("invalid sweep_id: {e}")))?;

    // Resolved under the SWEEP PRINCIPAL's live-data scope, not the eventual
    // reader's — a sweep key denied a source must not be able to launder that
    // source's events into a memory by citing their ids. The fact it produces is
    // then re-evaluated against every later reader's own scope, against the
    // manifest stamped here.
    let scope = auth.effective_viewer_scope();
    let resolver = nanosiem_core::hunts::ClickHouseEvidenceResolver::new(state.dual_pool());
    let resolved = resolver.resolve(&evidence_event_ids, &scope).await?;

    // `ResolvedEvidence::provenance` is complete only when NOTHING went
    // unresolved — which is also why an empty evidence list yields an incomplete
    // manifest rather than reading as "provably not source-derived".
    let provenance = resolved.provenance();
    // Only the ids that actually resolved are stored. Keeping an id that
    // resolved to nothing would put a pointer in the row that the manifest does
    // not account for.
    let stored_refs: Vec<String> = resolved
        .events
        .iter()
        .map(|event| event.canonical_event_id.clone())
        .collect();

    let (outcome, knowledge) = repository(&state)
        .record(
            &category,
            &subject,
            &fact,
            confidence,
            *sweep_id,
            &stored_refs,
            ttl_days,
            &provenance,
        )
        .await?;

    Ok(Json(RecordKnowledgeResponse { outcome, knowledge }))
}

/// Revoke a learned fact
///
/// Analyst-only, and permanent.
///
/// This is the human override on an agent's memory, and it is the reason the
/// store is safe to keep at all: "svc_backup is benign", recorded because
/// somebody spent two weeks making it look benign, is a slow-acting blindfold
/// unless somebody can take it away.
///
/// The revocation STICKS. The fact's identity slot is held permanently by the
/// tombstone, so a later sweep recording the same statement is refused and told
/// so rather than quietly inserting a fresh live row. The count of those refusals
/// is kept on the tombstone: if it climbs, either the revocation was wrong or
/// something keeps pushing the same narrative at the agent.
///
/// There is no un-revoke. The value of the guarantee is precisely that a sweep
/// cannot undo it, and an analyst-facing un-revoke is one misconfigured key away
/// from being the endpoint an agent's token gets pointed at next.
#[utoipa::path(
    post,
    path = "/api/hunts/knowledge/{id}/revoke",
    tag = "hunts",
    params(("id" = String, Path, description = "Knowledge TypeID")),
    request_body = RevokeKnowledgeRequest,
    responses(
        (status = 200, description = "Revoked; the tombstone is returned", body = HuntKnowledge),
        (status = 400, description = "A reason is required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, already revoked, or not visible under this caller's source scope"),
    ),
    security(("api_key" = []))
)]
pub async fn revoke_knowledge(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<RevokeKnowledgeRequest>,
) -> Result<Json<HuntKnowledge>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_TRIAGE)?;

    // Required, and required to be meaningful. A revocation is permanent and
    // "why" is the only thing that tells the next analyst whether to trust the
    // one before them.
    let reason = req.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::BadRequest(
            "a reason is required to revoke a learned fact".to_string(),
        ));
    }
    if reason.chars().count() > MAX_REVOKE_REASON_CHARS {
        return Err(ApiError::BadRequest(format!(
            "reason is longer than {MAX_REVOKE_REASON_CHARS} characters"
        )));
    }

    let revoked = repository(&state)
        .revoke(*id, reason, auth.user_id(), &artifact_scope(&auth))
        .await?
        // Not found / already revoked / invisible under this caller's scope are
        // ONE answer: distinguishing them would tell a caller that a fact they
        // may not read exists.
        .ok_or_else(|| ApiError::NotFound("Knowledge not found".to_string()))?;

    // `revoked_by` is ON DELETE SET NULL, so a departing employee's attribution
    // vanishes from the row. The audit log is the system of record for who
    // decided this, and it has to carry the subject and reason to be worth
    // reading later.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_KNOWLEDGE_REVOKED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_knowledge", Some(revoked.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "category": revoked.category,
                "subject": revoked.subject,
                "reason": reason,
                "relearn_attempts": revoked.relearn_attempts,
            }))
            .build(),
    );

    Ok(Json(revoked))
}

#[cfg(test)]
mod knowledge_boundary_tests {
    /// This module's own source, read at compile time.
    ///
    /// Self-referential on purpose: a path-relative `include_str!` travels with
    /// the file, so if the open-core mirror strips this module the test is
    /// stripped with it. An absolute `CARGO_MANIFEST_DIR` path would survive the
    /// strip and break the mirror build (NAN-2169).
    const SOURCE: &str = include_str!("knowledge.rs");

    fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
        let production = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source);
        production
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.is_empty()
            })
            .map(|(idx, line)| (idx + 1, line))
    }

    /// Knowledge INFORMS a sweep. It must never SUPPRESS a lead.
    ///
    /// The API layer is the easiest place for the coupling to arrive: one call
    /// to `service(&state).dismiss_lead(...)` inside `record_knowledge`, or a
    /// recall folded into the triage handlers, and a memory an attacker shaped
    /// becomes a reason a finding is never shown. Both halves look reasonable
    /// on their own, which is why this is a test and not a comment.
    ///
    /// The core-side counterpart —
    /// `knowledge_never_reaches_the_suppression_or_dismissal_path` in
    /// `nanosiem-core/src/hunts/knowledge_tests.rs` — guards the repository
    /// layer and the reverse direction.
    #[test]
    fn hunt_knowledge_stays_out_of_the_triage_path() {
        const FORBIDDEN: &[&str] = &["suppress", "dismiss", "hunt_leads", "promote_lead"];
        let mut violations = Vec::new();
        for (line_no, line) in code_lines(SOURCE) {
            let lowered = line.to_lowercase();
            for needle in FORBIDDEN {
                if lowered.contains(needle) {
                    violations.push(format!("knowledge.rs:{line_no} reaches `{needle}`: {}", line.trim()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "the knowledge handlers have been wired to lead suppression or dismissal \
             (NAN-2239). Knowledge belongs in the sweep's PROMPT and nowhere else — a poisoned \
             memory must cost the agent one misleading, not cost the analyst a finding they \
             never saw:\n{}",
            violations.join("\n")
        );

        // A scanner that matches nothing is indistinguishable from a clean file.
        assert!(
            SOURCE.contains("KnowledgeRepository"),
            "this guard is scanning the wrong file"
        );
    }

    /// The sibling handlers must not reach knowledge either.
    ///
    /// This is the direction that actually kills the invariant: "while I'm in
    /// the dismissal path, let me check what we already know about this entity"
    /// is a reasonable-sounding change, and this file's own source would stay
    /// spotless while it happened.
    ///
    /// `mod.rs` is exempt because it is pure wiring — module declarations,
    /// re-exports and the `utoipa` path list all necessarily name the handlers.
    /// It contains no logic that could act on a recalled fact.
    ///
    /// Read at RUNTIME rather than by `include_str!` so the test does not have
    /// to name every sibling and go stale the moment one is added.
    #[test]
    fn no_other_hunt_handler_consults_knowledge() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/hunts");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // Stripped or relocated tree: nothing to assert here.
            return;
        };
        let mut violations = Vec::new();
        let mut scanned = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if !name.ends_with(".rs") || name == "knowledge.rs" || name == "mod.rs" {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for (line_no, line) in code_lines(&source) {
                if line.to_lowercase().contains("knowledge") {
                    violations.push(format!("{name}:{line_no}: {}", line.trim()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "a hunt handler outside knowledge.rs consults hunt knowledge (NAN-2239). Recall is \
             a read a sweep performs BEFORE it starts looking; it must not be reachable from \
             triage, reporting or scoring:\n{}",
            violations.join("\n")
        );
        assert!(
            scanned >= 4,
            "expected to scan the sibling hunt handlers, scanned {scanned} — the directory \
             moved and this guard is looking at nothing"
        );
    }
}
