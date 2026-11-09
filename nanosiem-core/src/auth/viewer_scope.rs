// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed read principals for object-level visibility (NAN-5019 / NAN-5028).
//!
//! Before this module, case-linked reads took a bare `user_id: Uuid` and
//! applied only the case ACL, while the per-source deny set travelled (or did
//! not) as a separate `&BTreeSet<String>` argument. A caller could therefore
//! pass the user and forget the scope, and the repository had no way to tell
//! "unrestricted" from "forgotten". Notebook reads and the meloD summarizer did
//! exactly that.
//!
//! [`ViewerScope`] makes the pair ONE value: the ACL principal plus the
//! caller's effective live-data deny set. Repositories that gate on case
//! visibility take `&ViewerScope`, so the source half cannot be omitted.
//!
//! [`SystemScope`] is the explicit, named counterpart for background jobs. It
//! carries a [`SystemReason`] that is logged, so every unscoped read is
//! greppable and attributable.

use std::collections::BTreeSet;

use uuid::Uuid;

use super::scope::{deny_bind_values, ScopeSet};

/// A request principal's identity together with its per-source scope.
///
/// Build it from the authenticated request context (`AuthContext::viewer()` in
/// `nanosiem-api-lib`), never by pairing a user id with an empty scope: an
/// empty scope means "unrestricted", which is the privilege this type exists to
/// stop callers from granting by accident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewerScope {
    user_id: Uuid,
    scope: ScopeSet,
}

impl ViewerScope {
    /// Pair an ACL principal with its effective viewer scope (the LIVE-data
    /// half, including the `audit` gate — the same composition every case read
    /// uses).
    pub fn new(user_id: Uuid, scope: ScopeSet) -> Self {
        Self { user_id, scope }
    }

    /// The ACL principal (case creator / assignee / group member checks).
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// The full scope, for callers that hand it on to search/AI services.
    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    /// The live-data deny set.
    pub fn deny_set(&self) -> &BTreeSet<String> {
        self.scope.deny_set()
    }

    /// The normalized deny values to bind as a `text[]` parameter, or `None`
    /// for an unrestricted viewer. `None` means the caller must emit NO source
    /// predicate, keeping the SQL byte-identical to the pre-scoping form.
    pub fn deny_bind(&self) -> Option<Vec<String>> {
        let values = deny_bind_values(self.scope.deny_set());
        if values.is_empty() {
            None
        } else {
            Some(values)
        }
    }

    /// `Some(param)` when a source predicate must be emitted at `$param`.
    pub fn deny_param(&self, param: u16) -> Option<u16> {
        self.deny_bind().map(|_| param)
    }
}

/// Why a background job reads without a viewer scope.
///
/// Adding a variant is a reviewed decision: a SYSTEM read must not feed a
/// surface whose audience is narrower than what the job can see, unless the
/// output is filtered for that audience (see `shadow_investigation`
/// `case_history`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemReason {
    /// Automated case investigation (enterprise).
    ShadowInvestigation,
    /// Persisting the shared hunt profile (recon run / save).
    ReconProfile,
}

impl SystemReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SystemReason::ShadowInvestigation => "shadow_investigation",
            SystemReason::ReconProfile => "recon_profile",
        }
    }
}

/// An explicit, attributable unrestricted read principal for background jobs.
///
/// Deliberately has no `Default` and no constructor that takes a user, so it
/// cannot be mistaken for, or silently substituted by, a request scope.
#[derive(Debug)]
pub struct SystemScope {
    reason: SystemReason,
}

impl SystemScope {
    pub fn new(reason: SystemReason) -> Self {
        tracing::debug!(reason = reason.as_str(), "system-scope read principal created");
        Self { reason }
    }

    pub fn reason(&self) -> SystemReason {
        self.reason
    }

    /// The unrestricted scope this principal reads under.
    pub fn scope(&self) -> ScopeSet {
        ScopeSet::unrestricted()
    }
}
