// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed route authorization policy (NAN-2042).
//!
//! Today authorization is enforced ad hoc inside each handler via
//! `ensure_permission` / `has_permission`. A route is silently open the moment
//! a handler forgets its gate — the class of drift the NAN-2029 audit found
//! across search, streaming, OTEL, saved-search, field-discovery, case SSE,
//! health, and meloD paths. Source-scope deny sets and resource ownership are
//! *secondary* filters (they can default open, or be satisfied by an API-key
//! owner subject); neither is a positive capability boundary.
//!
//! [`RoutePolicy`] is the coarse, authoritative classification a route carries
//! so authorization can be enforced at the registration boundary rather than
//! (only) inside the handler. This module is the **pure decision core**: the
//! policy type, the minimal principal view it needs ([`RoutePrincipal`]), and
//! [`RoutePolicy::evaluate`]. Route-registration wiring, the enforcing
//! middleware, and production-app HTTP matrices live in each service. API and
//! enterprise registration use `nanosiem-api-lib::route_policy`; Search has its
//! own registration adapter to the same decision core.
//!
//! ## Model: auth mode × capability are independent
//!
//! A route's boundary is two orthogonal requirements, composed:
//!
//! * an [`AuthMode`] — is authentication required, and must it be an
//!   interactive session (API keys denied)?
//! * a [`CapabilityRequirement`] — which permission(s), on top of the auth
//!   mode?
//!
//! Keeping them independent is what lets the registry express routes that need
//! *both* — e.g. `POST /api/api-keys` requires an interactive session **and**
//! `api_keys:create`. A flat "one of N modes" enum could represent
//! "session-only" **or** "has-permission" but not their conjunction, leaving
//! exactly those routes dependent on the ad hoc handler checks this registry is
//! meant to supersede.
//!
//! **Layering contract:** the policy enforces the coarse capability / auth mode
//! FIRST; a handler may then apply ownership, case visibility, source scope, or
//! row filtering as defense in depth. Capability first, ownership/scope second.

use std::borrow::Cow;

/// The minimal view of an authenticated caller that a [`RoutePolicy`] needs to
/// reach a decision.
///
/// Each HTTP service has its own `AuthContext` type (`nanosiem-api-lib` for
/// `nanosiem-api` / the enterprise crate, and a separate one in
/// `nanosiem-search`). Implementing this trait on each lets the decision logic
/// in [`RoutePolicy::evaluate`] be written once and shared across all three,
/// instead of re-deriving it per service (the divergence class NAN-2043 was
/// about).
pub trait RoutePrincipal {
    /// True when the caller authenticated with an API key (as opposed to an
    /// interactive JWT/cookie session).
    fn is_api_key(&self) -> bool;

    /// Only a positively identified interactive session may satisfy this mode.
    fn is_interactive_session(&self) -> bool {
        false
    }

    /// Supplied only by verified internal service authentication, never headers.
    fn service_identity(&self) -> Option<&str> {
        None
    }

    /// True when the caller holds `permission`.
    fn has_permission(&self, permission: &str) -> bool;

    /// True when the caller holds at least one of `permissions`. Defaulted in
    /// terms of [`has_permission`](Self::has_permission); services may override
    /// with a more efficient implementation.
    fn has_any_permission(&self, permissions: &[&str]) -> bool {
        permissions.iter().any(|p| self.has_permission(p))
    }
}

/// The authentication mode a route requires (NAN-2042). Orthogonal to the
/// [`CapabilityRequirement`] — a [`RoutePolicy`] composes one of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// No authentication required. Reserved for an explicit, narrowly reviewed
    /// list (login, setup, OIDC callback, health-liveness, …). A `Public`
    /// route must not carry a capability requirement — there is no principal to
    /// check it against.
    Public,
    /// Any authenticated principal — session or API key.
    Authenticated,
    /// An authenticated interactive session (JWT / cookie). API keys are
    /// denied. For human-self / account-lifecycle routes where a
    /// service-to-service key must never act (mirrors
    /// `AuthContext::ensure_interactive_session`).
    InteractiveSession,
    /// A verified service on a private listener, with its own operation grants.
    ServiceIdentity(&'static str),
    /// Human self-service, or an explicitly granted administration capability.
    /// The handler must still bind the requested resource to the session owner.
    InteractiveOrCapability,
}

/// The permission requirement a route imposes **on top of** its [`AuthMode`]
/// (NAN-2042).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityRequirement {
    /// No permission check beyond the auth mode.
    None,
    /// The caller must hold **every** listed permission.
    AllOf(Cow<'static, [&'static str]>),
    /// The caller must hold **at least one** listed permission.
    AnyOf(Cow<'static, [&'static str]>),
    /// Every primary grant plus at least one declared alternative. Used where
    /// a common operation has two valid resource-specific authorities.
    AllOfAnyOf {
        all: &'static [&'static str],
        any: &'static [&'static str],
    },
}

/// The fail-closed authorization policy attached to a `(method, matched-path
/// template)` route (NAN-2042).
///
/// Auth mode and capability are independent fields so a route can require BOTH
/// an interactive session AND a permission (e.g. `POST /api/api-keys`), which a
/// flat mode enum could not express. Use the constructors ([`public`],
/// [`all_of`], [`interactive_all_of`], …) rather than building the struct by
/// hand — they keep the auth-mode / capability combination sensible (a
/// [`Public`] route never carries a capability).
///
/// A route with *no* policy at all is handled one layer up (the registry /
/// middleware), where the absence itself is a fail-closed **deny** plus a
/// high-signal signal — it is deliberately not representable here, so
/// "unclassified" can never be confused with "public".
///
/// [`public`]: RoutePolicy::public
/// [`all_of`]: RoutePolicy::all_of
/// [`interactive_all_of`]: RoutePolicy::interactive_all_of
/// [`Public`]: AuthMode::Public
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    /// The authentication mode gate, evaluated first.
    ///
    /// Private so the only way to build a `RoutePolicy` is through the
    /// constructors, which never produce the invalid `Public` + capability
    /// combination (a public route has no principal to check a permission
    /// against). Read via [`auth_mode`](RoutePolicy::auth_mode).
    auth_mode: AuthMode,
    /// The permission requirement, evaluated after the auth mode passes.
    /// Private for the same invariant; read via
    /// [`capability`](RoutePolicy::capability).
    capability: CapabilityRequirement,
}

/// The outcome of evaluating a [`RoutePolicy`] against a caller. Fail-closed:
/// anything short of an explicit grant is [`Deny`](PolicyDecision::Deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The caller satisfies the policy; the request may proceed to the handler.
    Allow,
    /// The caller does not satisfy the policy; the request must be rejected
    /// (403 for an authenticated caller, 401 when unauthenticated) before any
    /// body parsing, DB/ClickHouse access, or handler work.
    Deny,
}

impl PolicyDecision {
    /// True when the decision permits the request to proceed.
    pub fn is_allow(self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

impl RoutePolicy {
    /// No authentication and no capability required. The only variant that
    /// admits an unauthenticated caller.
    pub const fn public() -> Self {
        Self {
            auth_mode: AuthMode::Public,
            capability: CapabilityRequirement::None,
        }
    }

    /// Any authenticated principal (session or API key); no permission beyond
    /// authentication.
    pub const fn authenticated() -> Self {
        Self {
            auth_mode: AuthMode::Authenticated,
            capability: CapabilityRequirement::None,
        }
    }

    /// An authenticated interactive session (API keys denied); no permission
    /// beyond the session requirement.
    pub const fn interactive_session() -> Self {
        Self {
            auth_mode: AuthMode::InteractiveSession,
            capability: CapabilityRequirement::None,
        }
    }

    /// Any authenticated principal that holds **all** of `perms`.
    pub const fn all_of(perms: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::Authenticated,
            capability: CapabilityRequirement::AllOf(Cow::Borrowed(perms)),
        }
    }

    /// Any authenticated principal that holds **at least one** of `perms`.
    pub const fn any_of(perms: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::Authenticated,
            capability: CapabilityRequirement::AnyOf(Cow::Borrowed(perms)),
        }
    }

    /// An interactive session (API keys denied) that also holds **all** of
    /// `perms` — the session-gated capability boundary (e.g.
    /// `POST /api/api-keys` → interactive session + `api_keys:create`).
    pub const fn interactive_all_of(perms: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::InteractiveSession,
            capability: CapabilityRequirement::AllOf(Cow::Borrowed(perms)),
        }
    }

    /// An interactive session (API keys denied) that also holds **at least
    /// one** of `perms`.
    pub const fn interactive_any_of(perms: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::InteractiveSession,
            capability: CapabilityRequirement::AnyOf(Cow::Borrowed(perms)),
        }
    }

    /// A registration-time permission resolved from an existing typed operation.
    pub fn one(permission: &'static str) -> Self {
        Self {
            auth_mode: AuthMode::Authenticated,
            capability: CapabilityRequirement::AllOf(Cow::Owned(vec![permission])),
        }
    }

    pub fn service(identity: &'static str, operation: &'static str) -> Self {
        Self {
            auth_mode: AuthMode::ServiceIdentity(identity),
            capability: CapabilityRequirement::AllOf(Cow::Owned(vec![operation])),
        }
    }

    /// A service operation union (for protocols multiplexing commands on one URI).
    pub const fn service_any_of(
        identity: &'static str,
        operations: &'static [&'static str],
    ) -> Self {
        Self {
            auth_mode: AuthMode::ServiceIdentity(identity),
            capability: CapabilityRequirement::AnyOf(Cow::Borrowed(operations)),
        }
    }

    /// Preserve a capability requirement while requiring a positive session.
    pub fn interactive(mut self) -> Self {
        self.auth_mode = AuthMode::InteractiveSession;
        self
    }

    pub const fn interactive_or_all_of(perms: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::InteractiveOrCapability,
            capability: CapabilityRequirement::AllOf(Cow::Borrowed(perms)),
        }
    }

    pub const fn all_of_any_of(all: &'static [&'static str], any: &'static [&'static str]) -> Self {
        Self {
            auth_mode: AuthMode::Authenticated,
            capability: CapabilityRequirement::AllOfAnyOf { all, any },
        }
    }

    /// The authentication mode this policy requires.
    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// The capability requirement layered on top of the auth mode.
    pub fn capability(&self) -> &CapabilityRequirement {
        &self.capability
    }

    /// Evaluate this policy against the caller.
    ///
    /// `principal` is `None` for an unauthenticated request and `Some` once
    /// authentication has succeeded — so this must run *after* the auth
    /// middleware. Fail-closed by construction: the auth mode is checked first
    /// and, once it passes, the capability requirement; every branch returns
    /// [`Allow`](PolicyDecision::Allow) only on an explicit match and `Deny`
    /// otherwise (missing principal, an API key on an interactive-only route,
    /// a missing permission, or an empty permission set).
    pub fn evaluate<P: RoutePrincipal>(&self, principal: Option<&P>) -> PolicyDecision {
        use PolicyDecision::{Allow, Deny};

        // Invariant: a Public route carries no capability (the constructors —
        // the only way to build a RoutePolicy, since the fields are private —
        // never produce this pair). Defend against a malformed construction by
        // failing closed: a capability check is meaningless without a required
        // principal, and allowing it would contradict `is_public()`.
        if matches!(self.auth_mode, AuthMode::Public)
            && !matches!(self.capability, CapabilityRequirement::None)
        {
            return Deny;
        }

        // 1. Auth-mode gate. Resolve the principal that the capability check
        //    will run against, or short-circuit to Deny.
        let authed: Option<&P> = match self.auth_mode {
            // Public admits an unauthenticated caller; the principal (if any)
            // is passed through for the capability check below, though a
            // well-formed Public policy carries no capability.
            AuthMode::Public => principal,
            AuthMode::Authenticated => match principal {
                Some(p) => Some(p),
                None => return Deny,
            },
            AuthMode::InteractiveSession => match principal {
                Some(p) if p.is_interactive_session() => Some(p),
                _ => return Deny,
            },
            AuthMode::InteractiveOrCapability => match principal {
                Some(p) if p.is_interactive_session() => {
                    return match &self.capability {
                        CapabilityRequirement::AllOf(perms)
                            if !perms.is_empty() && perms.iter().all(|perm| !perm.is_empty()) =>
                        {
                            Allow
                        }
                        _ => Deny,
                    };
                }
                Some(p) => Some(p),
                None => return Deny,
            },
            AuthMode::ServiceIdentity(identity) => match principal {
                Some(p) if !identity.is_empty() && p.service_identity() == Some(identity) => {
                    Some(p)
                }
                _ => return Deny,
            },
        };

        // 2. Capability gate. Empty permission sets fail closed: without the
        //    `!is_empty()` guard, `Iterator::all` is vacuously true on `&[]`,
        //    so `AllOf(&[])` would grant any principal admitted by the auth
        //    mode — an empty set is always a registration mistake.
        match &self.capability {
            CapabilityRequirement::None => match self.auth_mode {
                // Public + no capability is the one unauthenticated allow.
                AuthMode::Public => Allow,
                // Authenticated / InteractiveSession with no capability: the
                // auth-mode gate above already proved a suitable principal.
                _ => Allow,
            },
            CapabilityRequirement::AllOf(perms) => match authed {
                Some(p)
                    if !perms.is_empty()
                        && perms
                            .iter()
                            .all(|perm| !perm.is_empty() && p.has_permission(perm)) =>
                {
                    Allow
                }
                _ => Deny,
            },
            CapabilityRequirement::AllOfAnyOf { all, any } => match authed {
                Some(p)
                    if !all.is_empty()
                        && !any.is_empty()
                        && all.iter().chain(any.iter()).all(|p| !p.is_empty())
                        && all.iter().all(|perm| p.has_permission(perm))
                        && p.has_any_permission(any) =>
                {
                    Allow
                }
                _ => Deny,
            },
            CapabilityRequirement::AnyOf(perms) => match authed {
                Some(p)
                    if !perms.is_empty()
                        && perms.iter().all(|perm| !perm.is_empty())
                        && p.has_any_permission(perms) =>
                {
                    Allow
                }
                _ => Deny,
            },
        }
    }

    /// True when this route admits unauthenticated callers. Used by the (future)
    /// middleware to decide whether to require a principal, and by the
    /// human-reviewable matrix to call out the public surface explicitly.
    pub fn is_public(&self) -> bool {
        matches!(self.auth_mode, AuthMode::Public)
    }

    /// True when reaching the handler requires an interactive session (API keys
    /// are denied regardless of their permissions).
    pub fn requires_interactive_session(&self) -> bool {
        matches!(self.auth_mode, AuthMode::InteractiveSession)
    }
}

/// One row of the route → policy matrix (NAN-2042): a `(method, matched-path
/// template)` and the [`RoutePolicy`] it carries.
///
/// The registration wrapper and completeness test (later phases) collect these
/// into the authoritative registry that CI checks against the actually-mounted
/// route set. Kept here as a pure data type so the matrix artifact and its
/// snapshot test can be built independently of the router wiring.
#[derive(Debug, Clone)]
pub struct RoutePolicyEntry {
    /// Uppercase HTTP method, e.g. `"GET"`, `"POST"`.
    pub method: &'static str,
    /// Axum matched-path template, e.g. `"/api/search"` or
    /// `"/api/playbooks/{id}"` — never a raw request path or prefix.
    pub path: &'static str,
    /// The policy enforced for this method + path.
    pub policy: RoutePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal [`RoutePrincipal`] test double so the decision core can be
    /// exercised without any service's `AuthContext` or DB infra.
    struct TestPrincipal {
        api_key: bool,
        perms: Vec<&'static str>,
    }

    impl TestPrincipal {
        fn session(perms: &[&'static str]) -> Self {
            Self {
                api_key: false,
                perms: perms.to_vec(),
            }
        }
        fn api_key(perms: &[&'static str]) -> Self {
            Self {
                api_key: true,
                perms: perms.to_vec(),
            }
        }
    }

    impl RoutePrincipal for TestPrincipal {
        fn is_api_key(&self) -> bool {
            self.api_key
        }
        fn is_interactive_session(&self) -> bool {
            !self.api_key
        }
        fn has_permission(&self, permission: &str) -> bool {
            self.perms.iter().any(|p| *p == permission)
        }
    }

    // `None` typed as `Option<&TestPrincipal>` for the unauthenticated cases.
    const ANON: Option<&TestPrincipal> = None;

    #[test]
    fn public_allows_everyone_including_anonymous() {
        let policy = RoutePolicy::public();
        assert!(policy.evaluate(ANON).is_allow());
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&[])))
            .is_allow());
        assert!(policy
            .evaluate(Some(&TestPrincipal::api_key(&[])))
            .is_allow());
        assert!(policy.is_public());
        assert!(!policy.requires_interactive_session());
    }

    #[test]
    fn authenticated_only_denies_anon_allows_any_principal() {
        let policy = RoutePolicy::authenticated();
        assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&[])))
            .is_allow());
        // An API key is still an authenticated principal here.
        assert!(policy
            .evaluate(Some(&TestPrincipal::api_key(&[])))
            .is_allow());
        assert!(!policy.is_public());
    }

    #[test]
    fn interactive_session_only_rejects_api_keys_and_anon() {
        let policy = RoutePolicy::interactive_session();
        assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::api_key(&[]))),
            PolicyDecision::Deny
        );
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&[])))
            .is_allow());
        assert!(policy.requires_interactive_session());
    }

    #[test]
    fn all_of_requires_every_permission() {
        let policy = RoutePolicy::all_of(&["search:execute", "search:sql"]);
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&[
                "search:execute",
                "search:sql"
            ])))
            .is_allow());
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::session(&["search:execute"]))),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::session(&[]))),
            PolicyDecision::Deny
        );
        assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
    }

    #[test]
    fn any_of_requires_at_least_one_permission() {
        let policy = RoutePolicy::any_of(&["cases:view", "cases:edit"]);
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&["cases:edit"])))
            .is_allow());
        // An unrelated permission does not satisfy the any-of set.
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::session(&["alerts:view"]))),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::session(&[]))),
            PolicyDecision::Deny
        );
        assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
    }

    #[test]
    fn empty_permission_sets_fail_closed() {
        // codex P1: an empty AllOf must NOT be vacuously satisfied — it would
        // otherwise let any auth-mode-admitted principal through. Both empty
        // AllOf and empty AnyOf deny everyone.
        for policy in [
            RoutePolicy::all_of(&[]),
            RoutePolicy::any_of(&[]),
            RoutePolicy::interactive_all_of(&[]),
            RoutePolicy::interactive_any_of(&[]),
        ] {
            assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
            assert_eq!(
                policy.evaluate(Some(&TestPrincipal::session(&["search:execute"]))),
                PolicyDecision::Deny,
                "empty permission set must fail closed even for a permissioned session"
            );
        }
    }

    #[test]
    fn api_key_with_the_permission_passes_capability_but_not_interactive_gate() {
        // A capability policy (auth_mode = Authenticated) admits an API key that
        // holds the permission; only the interactive gate bars keys. Source
        // scope / ownership remain the handler's defense-in-depth.
        assert!(RoutePolicy::all_of(&["search:execute"])
            .evaluate(Some(&TestPrincipal::api_key(&["search:execute"])))
            .is_allow());
        assert!(RoutePolicy::any_of(&["search:execute"])
            .evaluate(Some(&TestPrincipal::api_key(&["search:execute"])))
            .is_allow());
    }

    #[test]
    fn public_with_capability_is_rejected_fail_closed() {
        // codex P2: the constructors never build Public + capability, but the
        // in-module test can construct the malformed state directly (fields are
        // private to external code). `evaluate` must fail closed on it rather
        // than allowing a permissioned principal through a "public" route.
        let malformed = RoutePolicy {
            auth_mode: AuthMode::Public,
            capability: CapabilityRequirement::AllOf(Cow::Borrowed(&["search:execute"])),
        };
        assert_eq!(malformed.evaluate(ANON), PolicyDecision::Deny);
        assert_eq!(
            malformed.evaluate(Some(&TestPrincipal::session(&["search:execute"]))),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn constructors_never_produce_public_with_capability() {
        // The public construction surface (constructors) cannot express the
        // malformed state: the only Public constructor pairs it with None.
        assert_eq!(
            RoutePolicy::public().capability(),
            &CapabilityRequirement::None
        );
        assert!(RoutePolicy::public().is_public());
    }

    #[test]
    fn interactive_all_of_requires_both_session_and_permission() {
        // codex P1 (v2): the case a flat enum could not express — e.g.
        // POST /api/api-keys needs an interactive session AND api_keys:create.
        let policy = RoutePolicy::interactive_all_of(&["api_keys:create"]);

        // Session WITH the permission → allow.
        assert!(policy
            .evaluate(Some(&TestPrincipal::session(&["api_keys:create"])))
            .is_allow());
        // Session WITHOUT the permission → deny (unlike bare InteractiveSession,
        // which would have admitted a zero-permission session).
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::session(&[]))),
            PolicyDecision::Deny
        );
        // API key WITH the permission → deny (unlike bare AllOf, which would
        // have admitted a permissioned key).
        assert_eq!(
            policy.evaluate(Some(&TestPrincipal::api_key(&["api_keys:create"]))),
            PolicyDecision::Deny
        );
        // Unauthenticated → deny.
        assert_eq!(policy.evaluate(ANON), PolicyDecision::Deny);
        assert!(policy.requires_interactive_session());
    }
    #[test]
    fn service_identity_is_positive_exact_and_operation_bound() {
        struct Service {
            identity: Option<&'static str>,
            permission: &'static str,
        }
        impl RoutePrincipal for Service {
            fn is_api_key(&self) -> bool {
                false
            }
            fn service_identity(&self) -> Option<&str> {
                self.identity
            }
            fn has_permission(&self, p: &str) -> bool {
                p == self.permission
            }
        }
        let service = Service {
            identity: Some("platform"),
            permission: "tenant:provision",
        };
        let unknown = Service {
            identity: None,
            permission: "tenant:provision",
        };
        let other = Service {
            identity: Some("runner"),
            permission: "tenant:provision",
        };
        let policy = RoutePolicy::service("platform", "tenant:provision");
        assert!(policy.evaluate(Some(&service)).is_allow());
        assert!(!policy.evaluate(Some(&unknown)).is_allow());
        assert!(!policy.evaluate(Some(&other)).is_allow());
        assert!(!RoutePolicy::service("platform", "tenant:delete")
            .evaluate(Some(&service))
            .is_allow());
        assert!(!RoutePolicy::interactive_session()
            .evaluate(Some(&service))
            .is_allow());
        assert!(!RoutePolicy::interactive_session()
            .evaluate(Some(&unknown))
            .is_allow());
        assert!(!RoutePolicy::service("", "tenant:provision")
            .evaluate(Some(&service))
            .is_allow());
        let empty = Service {
            identity: Some("platform"),
            permission: "",
        };
        assert!(!RoutePolicy::service("platform", "")
            .evaluate(Some(&empty))
            .is_allow());
    }
    #[test]
    fn self_service_and_composite_alternatives_keep_positive_boundaries() {
        let self_service = RoutePolicy::interactive_or_all_of(&["users:edit"]);
        assert!(self_service
            .evaluate(Some(&TestPrincipal::session(&[])))
            .is_allow());
        assert!(!self_service
            .evaluate(Some(&TestPrincipal::api_key(&[])))
            .is_allow());
        assert!(self_service
            .evaluate(Some(&TestPrincipal::api_key(&["users:edit"])))
            .is_allow());
        assert!(!RoutePolicy::interactive_or_all_of(&[])
            .evaluate(Some(&TestPrincipal::session(&[])))
            .is_allow());
        let composite =
            RoutePolicy::all_of_any_of(&["melod:notebook"], &["notebooks:edit", "cases:edit"]);
        for api_key in [false, true] {
            for perms in [
                vec![],
                vec!["melod:notebook"],
                vec!["notebooks:edit"],
                vec!["cases:edit"],
            ] {
                let principal = TestPrincipal {
                    api_key,
                    perms: perms.to_vec(),
                };
                assert!(!composite.evaluate(Some(&principal)).is_allow());
            }
            for permissions in [
                ["melod:notebook", "notebooks:edit"],
                ["melod:notebook", "cases:edit"],
            ] {
                let principal = TestPrincipal {
                    api_key,
                    perms: permissions.to_vec(),
                };
                assert!(composite.evaluate(Some(&principal)).is_allow());
            }
        }
    }
}
