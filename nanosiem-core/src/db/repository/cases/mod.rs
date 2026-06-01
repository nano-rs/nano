// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case repository for CRUD operations
//!
//! Handles cases, alerts, entities, wall entries, relations, and grouping rules

mod alerts;
mod crud;
mod entities;
mod grouping_rules;
mod queues;
mod relations;
mod sharing;
mod wall;
mod workflow;

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

pub use workflow::CaseWorkflowRepository;

pub(crate) use crate::models::case::{
    AddAlertToCase, AssignCase, Case, CaseAffectedUser, CaseAlert, CaseAlertDetail,
    CaseDisposition, CaseEntity, CaseFilter, CaseFullResponse, CaseGroupingRule, CaseRelation,
    CaseResponseStats, CaseShareResult, CaseSort, CaseStats, CaseSummary, CaseWallEntry,
    CaseWallEntryWithCreator, CaseWithDetails, CaseWithDetailsRow, ChangeCaseStatus,
    EntityTypeSummary, NewCase, NewCaseEntity, NewCaseGroupingRule, NewCaseRelation,
    DuplicateCandidate, NewCaseWallEntry, RelatedCaseSummary, ShareCaseRequest, SharedGroup,
    SlaTargets, UpdateCase, UpdateCaseGroupingRule,
};

#[derive(Error, Debug)]
pub enum CaseRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Case not found: {0}")]
    NotFound(Uuid),
    #[error("Alert not found: {0}")]
    AlertNotFound(Uuid),
    #[error("Entity not found: {0}")]
    EntityNotFound(Uuid),
    #[error("Wall entry not found: {0}")]
    WallEntryNotFound(Uuid),
    #[error("Relation not found: {0}")]
    RelationNotFound(Uuid),
    #[error("Grouping rule not found: {0}")]
    GroupingRuleNotFound(Uuid),
    #[error("Alert already in case")]
    AlertAlreadyInCase,
    #[error("Entity already exists")]
    EntityAlreadyExists,
    #[error("Relation already exists")]
    RelationAlreadyExists,
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Access denied")]
    AccessDenied,
}

/// Repository for case operations
#[derive(Clone)]
pub struct CaseRepository {
    pool: PgPool,
}

impl CaseRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
