// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbooks module — SOC-managed investigation playbooks.
//!
//! Provides:
//!   * [`acl`] — per-playbook role ACL policy ([`PlaybookPrincipal`],
//!     [`PlaybookAction`]) enforced by every repository read and mutation.
//!   * [`composer`] — emits a promotable library-format doc from a Shadow
//!     Investigator notebook trail.
//!   * [`parser`] — markdown + slash-command parser (ported from the JS mock).
//!   * [`frontmatter`] — YAML frontmatter splitter.
//!   * [`models`] — Postgres row types + request/response DTOs.
//!   * [`repository`] — sqlx repository for the `playbooks` table family.
//!   * [`service`] — [`PlaybookService`] composing repo + parser.
//!   * [`error`] — [`PlaybookError`] type shared across the module.

pub mod acl;
pub mod composer;
pub mod error;
pub mod frontmatter;
pub mod models;
pub mod parser;
pub mod repository;
pub mod runtime;
pub mod service;

pub use acl::{PlaybookAction, PlaybookPrincipal, API_KEY_ROLE, DEMO_ROLE, SYNTHETIC_ROLES};
pub use composer::compose_adaptive_playbook_doc;
pub use error::PlaybookError;
pub use frontmatter::split_frontmatter;
pub use models::{
    AdaptiveSource, ApprovalResponseRequest, AttachToCaseRequest, CreatePlaybookRequest,
    DangerPolicy, FinishRunRequest, ForkPlaybookRequest, ListPlaybooksQuery, ParsedStepTree,
    Playbook, PlaybookAnalytics, PlaybookApproval, PlaybookCategory, PlaybookFrontmatter,
    PlaybookListResponse, PlaybookPermission, PlaybookPhase, PlaybookRun, PlaybookScope,
    PlaybookStatus, PlaybookStep, PlaybookSuggestion, PlaybookVersion, ResolvedRunResponse,
    SetPermissionRequest, SubmitForReviewRequest, UpdatePlaybookRequest,
    UpdateStepCompletionRequest, WhenClause, WhenOp,
};
pub use parser::{eval_when, normalize_answer, parse_playbook, parse_step_body, parse_when_clause, WhenResult};
pub use repository::PlaybookRepository;
pub use service::PlaybookService;
