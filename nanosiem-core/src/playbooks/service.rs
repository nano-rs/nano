// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbook service — composes the repository with the markdown parser.
//!
//! Responsibilities:
//!   * Parse the playbook `doc` into `parsed_steps` on create / update.
//!   * Handle fork semantics (deep copy doc + meta, clear adaptive_source).
//!   * Provide a thin layer above the repository for the API handlers to call.

use serde_json::Value;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use super::acl::PlaybookPrincipal;
use super::error::PlaybookError;
use super::models::{
    AttachToCaseRequest, CreatePlaybookRequest, FinishRunRequest, ForkPlaybookRequest,
    ListPlaybooksQuery, Playbook, PlaybookApproval, PlaybookListResponse, PlaybookPermission,
    PlaybookRun, PlaybookSuggestion, PlaybookVersion, SetPermissionRequest,
    SubmitForReviewRequest, UpdatePlaybookRequest,
};
use super::parser::parse_playbook;
use super::repository::PlaybookRepository;

/// Service for managing playbooks.
#[derive(Clone)]
pub struct PlaybookService {
    repo: PlaybookRepository,
}

impl PlaybookService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: PlaybookRepository::new(pool),
        }
    }

    pub fn repo(&self) -> &PlaybookRepository {
        &self.repo
    }

    // =========================================================================
    // List / Get
    // =========================================================================

    pub async fn list(
        &self,
        query: &ListPlaybooksQuery,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookListResponse, PlaybookError> {
        let playbooks = self.repo.list(query, principal).await?;
        let total = self.repo.count(query, principal).await?;
        Ok(PlaybookListResponse { playbooks, total })
    }

    pub async fn get(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        self.repo.get(id, principal).await
    }

    pub async fn list_by_signal(
        &self,
        signals: &[String],
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<Playbook>, PlaybookError> {
        self.repo.list_by_signal(signals, principal).await
    }

    // =========================================================================
    // Create / Update
    // =========================================================================

    pub async fn create(
        &self,
        req: CreatePlaybookRequest,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, PlaybookError> {
        let parsed = parse_and_serialize(&req.doc);
        self.repo.create(&req, parsed.as_ref(), user_id).await
    }

    pub async fn update(
        &self,
        id: Uuid,
        req: UpdatePlaybookRequest,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        // Only re-parse if doc was provided.
        let parsed = match req.doc.as_ref() {
            Some(doc) => parse_and_serialize(doc),
            None => None,
        };
        self.repo
            .update(id, &req, parsed.as_ref(), user_id, principal)
            .await
    }

    pub async fn archive(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        self.repo.archive(id, principal).await
    }

    /// NAN-456: hard delete — permanently removes the playbook row. Archive
    /// is the soft-delete path for keeping history. Use this only for junk
    /// (e.g. mis-imported README.md) or deliberate removal.
    pub async fn delete(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        self.repo.delete(id, principal).await
    }

    pub async fn fork(
        &self,
        id: Uuid,
        req: ForkPlaybookRequest,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        self.repo.fork(id, &req, user_id, principal).await
    }

    // =========================================================================
    // Children
    // =========================================================================

    // NAN-2097: every `{id}`-scoped child read below opens with
    // `repo.get(id, principal)`, which carries the VIEW predicate — so a caller
    // the ACL denies gets the same `NotFound` for the child collection as for
    // the playbook itself, and the child query never runs.

    pub async fn list_versions(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookVersion>, PlaybookError> {
        // Validate playbook exists AND is visible first, for a clean 404 —
        // `list_versions` re-applies the predicate itself, but an empty list and
        // a hidden playbook must not be conflated in the response.
        let _ = self.repo.get(id, principal).await?;
        self.repo.list_versions(id, principal).await
    }

    /// List a playbook's runs visible to `user_id` (NAN-2044 — runs whose case
    /// the caller cannot see are excluded; see `PlaybookRepository::list_runs`).
    pub async fn list_runs(
        &self,
        id: Uuid,
        user_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookRun>, PlaybookError> {
        let _ = self.repo.get(id, principal).await?;
        self.repo.list_runs(id, user_id, principal).await
    }

    pub async fn list_permissions(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookPermission>, PlaybookError> {
        let _ = self.repo.get(id, principal).await?;
        self.repo.list_permissions(id, principal).await
    }

    pub async fn list_approvals(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookApproval>, PlaybookError> {
        let _ = self.repo.get(id, principal).await?;
        self.repo.list_approvals(id, principal).await
    }

    // ========================================================================
    // NAN-445 — suggest + run mutations
    // ========================================================================

    /// Suggest playbooks for a given rule. Builds a signal set from:
    ///   rule.id (as string) + rule.name + mitre_tactics + mitre_techniques.
    /// Falls back to `rule.folder -> playbook.category` when no signals match.
    ///
    /// NAN-2104: the caller must independently hold `detections:view` — this
    /// reads an arbitrary detection rule's name, folder and MITRE mappings by
    /// caller-supplied id, and its 200/404 split is a rule-existence oracle. The
    /// gate lives on the handler, alongside `playbooks:view`.
    /// NAN-2097: the returned playbooks are ACL-filtered in SQL.
    pub async fn suggest_for_rule(
        &self,
        rule_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookSuggestion>, PlaybookError> {
        let rule = self.repo.get_rule_signal_context(rule_id).await?;

        let mut signals: Vec<String> = Vec::new();
        signals.push(rule.id.to_string());
        if !rule.name.is_empty() {
            signals.push(rule.name.clone());
        }
        signals.extend(rule.mitre_tactics.iter().cloned());
        signals.extend(rule.mitre_techniques.iter().cloned());

        let category = rule.folder.as_deref();
        let rows = self
            .repo
            .suggest_by_signals(&signals, category, principal)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(pb, score, matched)| {
                let matched_by_category = category
                    .map(|c| pb.category == c)
                    .unwrap_or(false);
                PlaybookSuggestion {
                    playbook: pb,
                    score,
                    matched_signals: matched,
                    matched_by_category,
                }
            })
            .collect())
    }

    /// Attach a playbook to a case. Creates a new `playbook_runs` row in the
    /// `active` state. The repository resolves the playbook's `current_version`
    /// when the request doesn't pin a version.
    ///
    /// NAN-469 — manual-attach path: when no alert seed is available, build a
    /// frozen `run_context` snapshot from the live case (case fields + the
    /// case's already-extracted entities). This lets `{{case.id}}`,
    /// `{{entity.user}}`, etc. resolve at render time. `alert.*` / `event.*`
    /// tokens stay unresolved (the runtime renders them as empty strings —
    /// known-namespace, missing-data is intentionally silent). Snapshot is
    /// frozen at attach time per `playbook_runs.run_context` semantics —
    /// re-attach captures a fresh snapshot.
    ///
    /// Snapshot building is best-effort: if the case row is missing or the
    /// entity fetch fails, we log and fall back to creating the run with
    /// `run_context = NULL` so the manual attach still succeeds (mirrors the
    /// behaviour the rule-fire auto-attach path uses for its own enrichment
    /// failures).
    pub async fn attach_to_case(
        &self,
        playbook_id: Uuid,
        req: AttachToCaseRequest,
        operator_user_id: Option<Uuid>,
        operator_label: Option<String>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        let run_context = match self.repo.fetch_case_snapshot_inputs(req.case_id).await {
            Ok(inputs) => {
                let case_tid = crate::typeid::encode("case", &req.case_id);
                Some(crate::playbooks::runtime::build_snapshot_from_case(
                    &case_tid,
                    Some(&inputs.title),
                    Some(&inputs.severity),
                    &inputs.entities,
                ))
            }
            Err(err) => {
                warn!(
                    case_id = %req.case_id,
                    error = %err,
                    "Failed to fetch case snapshot inputs for manual playbook attach; \
                     proceeding with empty run_context",
                );
                None
            }
        };

        self.repo
            .create_run(
                playbook_id,
                req.version,
                req.case_id,
                operator_user_id,
                operator_label,
                run_context,
                user_id,
                principal,
            )
            .await
    }

    /// NAN-463 — upsert a single step's completion entry on a run.
    /// Thin wrapper around the repo method; the audit trail lives in
    /// `playbook_runs.step_completion` itself.
    pub async fn update_step_completion(
        &self,
        run_id: Uuid,
        step_id: &str,
        req: crate::playbooks::models::UpdateStepCompletionRequest,
        operator_user_id: Option<Uuid>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        self.repo
            .update_step_completion(
                run_id,
                step_id,
                req.completed,
                req.skipped,
                req.note,
                operator_user_id,
                user_id,
                principal,
            )
            .await
    }

    /// Finish a run (mark `resolved` + compute TTR).
    pub async fn finish_run(
        &self,
        run_id: Uuid,
        req: FinishRunRequest,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        // NAN-475: weave the typed `note` into step_completion under the
        // synthetic `__run__` step id so it co-locates with the documented
        // per-step schema. Preserves any caller-supplied step entries.
        let step_completion = match (req.step_completion, req.note) {
            (sc, None) => sc,
            (sc, Some(note)) if note.trim().is_empty() => sc,
            (sc, Some(note)) => Some(merge_finish_note(sc, &note)),
        };
        self.repo
            .finish_run(run_id, req.outcome, step_completion, user_id, principal)
            .await
    }

    /// Surface a run by id (used by case views). Gated on the caller's VIEW
    /// grant for the run's playbook (NAN-2097); callers that render
    /// `run_context` must additionally apply the case-visibility check
    /// (NAN-2044) — see [`Self::resolve_run`].
    pub async fn get_run(
        &self,
        run_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        self.repo.get_run(run_id, principal).await
    }


    /// NAN-462 — resolve a run's playbook doc against its frozen
    /// `run_context` snapshot. Fetches the run + its version's doc, parses
    /// the doc, and substitutes every `{{...}}` token in every step's label
    /// + params (+ options) against the snapshot. Legacy or manual-attach
    /// runs without context get `has_context = false` and the tree is
    /// returned unresolved (tokens stay literal).
    pub async fn resolve_run(
        &self,
        run_id: Uuid,
        user_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<crate::playbooks::models::ResolvedRunResponse, PlaybookError> {
        use crate::playbooks::runtime::{resolve_step, RunContext};

        // NAN-2097: the run lookup carries the playbook VIEW predicate, and
        // `get_version_doc` below re-applies it — resolving a run renders the
        // playbook's full step tree, so it is a playbook read as much as a case
        // read. Both gates yield NotFound, so neither is an existence oracle.
        let run = self.repo.get_run(run_id, principal).await?;
        // NAN-2044: the resolved doc embeds the run's frozen case run_context,
        // so the caller must be able to SEE that case — cases:view (the
        // capability) is not permission over this specific case. 404 (via
        // NotFound) when it isn't visible, so run existence isn't leaked.
        if !self.repo.case_visible_to(run.case_id, user_id).await? {
            return Err(PlaybookError::NotFound(run_id));
        }
        let doc = self
            .repo
            .get_version_doc(run.playbook_id, run.playbook_version, principal)
            .await?;
        let mut tree = crate::playbooks::parser::parse_playbook(&doc);

        let ctx: Option<RunContext> = run
            .run_context
            .as_ref()
            .and_then(|v| serde_json::from_value::<RunContext>(v.clone()).ok());

        let has_context = ctx.is_some();
        let mut unresolved: Vec<String> = Vec::new();

        if let Some(ctx) = ctx {
            // Resolve orphan steps first (ones not under a phase heading),
            // then each phase's steps.
            for step in tree.steps.iter_mut() {
                let (resolved, u) = resolve_step(step, &ctx);
                *step = resolved;
                unresolved.extend(u);
            }
            for phase in tree.phases.iter_mut() {
                for step in phase.steps.iter_mut() {
                    let (resolved, u) = resolve_step(step, &ctx);
                    *step = resolved;
                    unresolved.extend(u);
                }
            }
            // De-dup unresolved paths — same {{widget.foo}} appearing in
            // five steps shouldn't produce five indicator hits.
            unresolved.sort();
            unresolved.dedup();
        }

        Ok(crate::playbooks::models::ResolvedRunResponse {
            has_context,
            tree,
            unresolved,
        })
    }

    /// List all playbook runs attached to a case VISIBLE to `user_id`
    /// (NAN-2044). Reading a case's runs reads that case's data, so a caller
    /// who cannot see the case gets `NotFound` rather than its runs.
    pub async fn list_runs_for_case(
        &self,
        case_id: Uuid,
        user_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookRun>, PlaybookError> {
        if !self.repo.case_visible_to(case_id, user_id).await? {
            return Err(PlaybookError::NotFound(case_id));
        }
        // NAN-2097: runs of playbooks the caller cannot VIEW are excluded, so a
        // shared case cannot become a side door onto a restricted playbook.
        self.repo.list_runs_for_case(case_id, principal).await
    }

    // ========================================================================
    // NAN-446 — Phase 5: adaptive → library promote
    // ========================================================================

    /// Promote an adaptive playbook into the library. Idempotent on
    /// already-promoted rows.
    pub async fn promote(
        &self,
        playbook_id: Uuid,
        promoted_by_user_id: Option<Uuid>,
        promoted_by_name: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        self.repo
            .promote(playbook_id, promoted_by_user_id, promoted_by_name, principal)
            .await
    }

    // ========================================================================
    // NAN-447 — Phase 6: approval workflow + permissions
    // ========================================================================

    pub async fn submit_for_review(
        &self,
        playbook_id: Uuid,
        requester_id: Option<Uuid>,
        req: SubmitForReviewRequest,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        self.repo
            .submit_for_review(
                playbook_id,
                requester_id,
                req.approver_id,
                req.message,
                principal,
            )
            .await
    }

    /// Respond to an approval (NAN-2098).
    ///
    /// `responder_id` is ATTRIBUTION — who is recorded as the approver when the
    /// approval was open. `assignee_claim` is AUTHORIZATION — the identity
    /// allowed to answer an approval already assigned to a specific reviewer.
    /// They are separate parameters on purpose: for an API key `auth.user_id()`
    /// is the key's OWNER, and NAN-2145 established that an owner-subject may be
    /// used for attribution but never for an authorization decision. Handlers
    /// therefore pass `assignee_claim = None` for API keys, which reduces the
    /// SQL predicate to `approver_id IS NULL` — a key can answer OPEN approvals
    /// only, and can never impersonate a designated human reviewer.
    pub async fn approve(
        &self,
        approval_id: Uuid,
        responder_id: Option<Uuid>,
        assignee_claim: Option<Uuid>,
        response: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        self.repo
            .approve_approval(
                approval_id,
                responder_id,
                assignee_claim,
                response,
                principal,
            )
            .await
    }

    /// Reject an approval. Same authorization rule as [`Self::approve`].
    pub async fn reject(
        &self,
        approval_id: Uuid,
        responder_id: Option<Uuid>,
        assignee_claim: Option<Uuid>,
        response: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        self.repo
            .reject_approval(
                approval_id,
                responder_id,
                assignee_claim,
                response,
                principal,
            )
            .await
    }

    pub async fn upsert_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
        req: SetPermissionRequest,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookPermission, PlaybookError> {
        self.repo
            .upsert_permission(
                playbook_id,
                role,
                req.can_view,
                req.can_run,
                req.can_edit,
                req.can_publish,
                req.member_count,
                principal,
            )
            .await
    }

    pub async fn delete_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        self.repo
            .delete_permission(playbook_id, role, principal)
            .await
    }

    // ========================================================================
    // NAN-448 — Phase 7: analytics
    // ========================================================================

    pub async fn compute_analytics(
        &self,
        playbook_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<super::models::PlaybookAnalytics, PlaybookError> {
        // Validate existence AND visibility first — returns NotFound cleanly.
        // `compute_analytics` re-probes internally; both are cheap.
        let _ = self.repo.get(playbook_id, principal).await?;
        self.repo.compute_analytics(playbook_id, principal).await
    }

    // ========================================================================
    // NAN-449 — Phase 5b: adaptive composition from a case
    // ========================================================================

    /// Compose an adaptive playbook from a case's Shadow Investigator notebook
    /// entries. Returns the newly-created (or no-op: existing) playbook row.
    ///
    /// Flow:
    ///   1. Fetch notebook entries for the case (via repository SQL)
    ///   2. Fetch the source rule's name + folder to seed title + category
    ///   3. Call `playbooks::composer::compose_adaptive_playbook_doc` to build
    ///      slash-command markdown
    ///   4. Parse the doc into a step tree (caches as `parsed_steps`)
    ///   5. INSERT `playbooks` row with `adaptive = TRUE`
    ///
    /// Returns `PlaybookError::NotFound(case_id)` if there are no
    /// shadow_investigation notebook entries to compose from.
    pub async fn compose_adaptive_from_case(
        &self,
        case_id: Uuid,
        composed_by_user_id: Option<Uuid>,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, PlaybookError> {
        // NAN-2044: the entry read is gated on $user's case visibility (atomic,
        // in the query) — a caller who cannot see the case gets no entries and
        // this composes nothing (NotFound), so private investigation notes are
        // never returned in a composed playbook.
        let entries = self
            .repo
            .fetch_case_notebook_entries(case_id, user_id)
            .await?;
        let rule_name = self.repo.fetch_case_rule_name(case_id).await?;
        let rule_folder = self.repo.fetch_case_category(case_id).await?;

        let doc = crate::playbooks::composer::compose_adaptive_playbook_doc(
            &entries,
            rule_name.as_deref(),
        )
        .ok_or(PlaybookError::NotFound(case_id))?;

        // Map rule.folder to a valid PlaybookCategory (fallback: identity).
        let category = match rule_folder.as_deref() {
            Some(f) if matches!(f, "identity" | "endpoint" | "cloud" | "data" | "network" | "email") => f,
            _ => "identity",
        };

        let parsed_steps = parse_and_serialize(&doc);

        let title = rule_name
            .as_deref()
            .map(|n| format!("Adaptive · {n}"))
            .unwrap_or_else(|| "Adaptive · Shadow Investigator".to_string());
        let subtitle = format!("Composed from case {case_id} · review before promoting");

        self.repo
            .insert_adaptive_from_case(
                case_id,
                composed_by_user_id,
                &title,
                Some(&subtitle),
                category,
                &doc,
                parsed_steps,
                "shadow_investigator",
            )
            .await
    }
}

/// Parse the doc into a `ParsedStepTree` and serialize it as a JSON Value
/// for storage in the `parsed_steps` column. Returns `None` if serialization
/// fails (unexpected — the parser's output is always serializable).
///
/// `pub(crate)` because hunts populate the same column through their own write
/// path (`crate::hunts::repository`) — the step-tree cache is a property of the
/// shared definition layer, not of response playbooks.
pub(crate) fn parse_and_serialize(doc: &str) -> Option<Value> {
    let tree = parse_playbook(doc);
    match serde_json::to_value(&tree) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(error = %e, "Failed to serialize parsed playbook step tree");
            None
        }
    }
}

/// NAN-475: merge a closing-note string into a `step_completion` JSONB blob
/// under the synthetic step id `__run__`. If the input isn't an object,
/// it's replaced with a fresh object — the caller's malformed value is
/// dropped (UI never produces non-object step_completion).
fn merge_finish_note(step_completion: Option<Value>, note: &str) -> Value {
    let mut obj = match step_completion {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    let mut entry = match obj.remove("__run__") {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    entry.insert("operator_note".into(), Value::String(note.to_string()));
    obj.insert("__run__".into(), Value::Object(entry));
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_finish_note_into_empty_step_completion() {
        let merged = merge_finish_note(None, "did the thing");
        assert_eq!(
            merged,
            json!({ "__run__": { "operator_note": "did the thing" } })
        );
    }

    #[test]
    fn merge_finish_note_preserves_existing_step_entries() {
        let existing = json!({
            "step_a": { "completed_at": "2026-01-01T00:00:00Z" },
            "step_b": { "skipped": true },
        });
        let merged = merge_finish_note(Some(existing), "wrap-up note");
        assert_eq!(
            merged,
            json!({
                "step_a": { "completed_at": "2026-01-01T00:00:00Z" },
                "step_b": { "skipped": true },
                "__run__": { "operator_note": "wrap-up note" },
            })
        );
    }

    #[test]
    fn merge_finish_note_replaces_only_operator_note_on_existing_run_entry() {
        let existing = json!({
            "__run__": { "completed_at": "2026-01-01T00:00:00Z", "operator_note": "old" },
        });
        let merged = merge_finish_note(Some(existing), "new");
        assert_eq!(
            merged,
            json!({
                "__run__": { "completed_at": "2026-01-01T00:00:00Z", "operator_note": "new" },
            })
        );
    }

    #[test]
    fn merge_finish_note_recovers_from_non_object_step_completion() {
        let merged = merge_finish_note(Some(json!("garbage")), "note");
        assert_eq!(merged, json!({ "__run__": { "operator_note": "note" } }));
    }
}
