// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed route registration. Method, handler and policy are inseparable;
//! merged routers retain their complete runtime inventory.
use crate::AuthContext;
use axum::{
    extract::{MatchedPath, Request, State},
    handler::Handler,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::Route,
};
use nanosiem_core::auth::route_policy::{RoutePolicy, RoutePrincipal};
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};
use tower::{Layer, Service};

impl RoutePrincipal for AuthContext {
    fn is_api_key(&self) -> bool {
        self.is_api_key
    }
    fn is_interactive_session(&self) -> bool {
        !self.is_api_key && self.api_key_id.is_none() && self.claims.purpose == "access"
    }
    fn has_permission(&self, permission: &str) -> bool {
        self.has_permission(permission)
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub method: &'static str,
    pub path: String,
    pub policy: RoutePolicy,
}

/// No constructor accepts a bare Axum MethodRouter: every mounted method must
/// be created by the policy-bearing routing functions below.
#[derive(Clone)]
pub struct Methods<S> {
    router: axum::routing::MethodRouter<S>,
    policies: Vec<(&'static str, RoutePolicy)>,
}
impl<S: Clone + Send + Sync + 'static> Methods<S> {
    pub fn layer<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        Self {
            router: self.router.layer(layer),
            policies: self.policies,
        }
    }
}

pub mod routing {
    use super::*;
    macro_rules! method {
        ($name:ident, $upper:literal) => {
            pub fn $name<H, T, S>(handler: H, policy: RoutePolicy) -> Methods<S>
            where
                H: Handler<T, S>,
                T: 'static,
                S: Clone + Send + Sync + 'static,
            {
                Methods {
                    router: axum::routing::$name(handler),
                    policies: vec![($upper, policy)],
                }
            }
            impl<S: Clone + Send + Sync + 'static> Methods<S> {
                pub fn $name<H, T>(mut self, handler: H, policy: RoutePolicy) -> Self
                where
                    H: Handler<T, S>,
                    T: 'static,
                {
                    assert!(
                        !self.policies.iter().any(|(m, _)| *m == $upper),
                        "duplicate route method"
                    );
                    self.router = self.router.$name(handler);
                    self.policies.push(($upper, policy));
                    self
                }
            }
        };
    }
    method!(get, "GET");
    method!(post, "POST");
    method!(put, "PUT");
    method!(patch, "PATCH");
    method!(delete, "DELETE");
    method!(head, "HEAD");
    method!(options, "OPTIONS");
    method!(trace, "TRACE");
    method!(connect, "CONNECT");
}

/// Registration-only router. `into_router` installs default-deny enforcement;
/// `with_state` does the same before supplying the production state. Authentication
/// must wrap the returned Axum router, so policy runs after principal resolution.
#[derive(Clone)]
pub struct Router<S = ()> {
    router: axum::Router<S>,
    entries: Vec<Entry>,
}
impl<S: Clone + Send + Sync + 'static> Default for Router<S> {
    fn default() -> Self {
        Self::new()
    }
}
impl<S: Clone + Send + Sync + 'static> Router<S> {
    pub fn new() -> Self {
        Self {
            router: axum::Router::new(),
            entries: vec![],
        }
    }
    pub fn route(mut self, path: &str, methods: Methods<S>) -> Self {
        for (method, policy) in methods.policies {
            assert!(
                !self
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.method == method),
                "duplicate route policy: {method} {path}"
            );
            self.entries.push(Entry {
                method,
                path: path.into(),
                policy,
            });
        }
        self.router = self.router.route(path, methods.router);
        self
    }
    pub fn route_if(self, condition: bool, path: &str, methods: Methods<S>) -> Self {
        if condition {
            self.route(path, methods)
        } else {
            self
        }
    }
    pub fn merge(mut self, other: Self) -> Self {
        for entry in &other.entries {
            assert!(
                !self
                    .entries
                    .iter()
                    .any(|e| e.path == entry.path && e.method == entry.method),
                "duplicate merged route policy: {} {}",
                entry.method,
                entry.path
            );
        }
        self.router = self.router.merge(other.router);
        self.entries.extend(other.entries);
        self
    }
    pub fn layer<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        Self {
            router: self.router.layer(layer),
            entries: self.entries,
        }
    }
    pub fn route_layer<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        Self {
            router: self.router.route_layer(layer),
            entries: self.entries,
        }
    }
    /// Bind a subservice's state while retaining registration metadata for the
    /// final listener inventory. Enforcement is installed only when sealed.
    pub fn with_inner_state<S2: Clone + Send + Sync + 'static>(self, state: S) -> Router<S2> {
        Router {
            router: self.router.with_state(state),
            entries: self.entries,
        }
    }

    /// Adapter for third-party generated documentation routes. The enclosing
    /// default-deny guard rejects any generated method/template omitted here.
    pub fn documented(router: axum::Router<S>, paths: &[&str], policy: RoutePolicy) -> Self {
        Self {
            router,
            entries: paths
                .iter()
                .map(|path| Entry {
                    method: "GET",
                    path: (*path).into(),
                    policy: policy.clone(),
                })
                .collect(),
        }
    }

    pub fn manifest(&self) -> &[Entry] {
        &self.entries
    }
    pub fn into_router(self) -> axum::Router<S> {
        let registry = Arc::new(Registry::new(self.entries));
        self.router
            .layer(axum::middleware::from_fn_with_state(registry, enforce))
    }
    /// Seal a physically separate service listener: credential resolution runs
    /// before the shared policy guard, for the exact registered service only.
    pub fn into_private_router(self, authenticators: ServiceAuthenticators) -> axum::Router<S> {
        let registry = Arc::new(Registry::new(self.entries.clone()));
        private_listener(
            self.into_router()
                .layer(axum::middleware::from_fn_with_state(
                    (registry, authenticators),
                    authenticate_registered_service,
                )),
        )
    }

    pub fn with_state<S2: Clone + Send + Sync + 'static>(self, state: S) -> axum::Router<S2> {
        self.into_router().with_state(state)
    }
}

#[derive(Clone)]
pub struct Registry(BTreeMap<(String, String), RoutePolicy>);
impl Registry {
    pub fn new(entries: Vec<Entry>) -> Self {
        let mut rows = BTreeMap::new();
        for entry in entries {
            assert!(
                rows.insert((entry.method.into(), entry.path), entry.policy)
                    .is_none(),
                "duplicate policy"
            );
        }
        Self(rows)
    }
    pub fn policy(&self, method: &Method, path: &str) -> Option<&RoutePolicy> {
        self.0
            .get(&(method.as_str().into(), path.into()))
            .or_else(|| {
                (method == Method::HEAD)
                    .then(|| self.0.get(&("GET".into(), path.into())))
                    .flatten()
            })
    }
}
/// Only authentication middleware constructs this after verifying the service
/// credential. It is process-owned extension data, never deserialized from HTTP.
#[derive(Clone, Debug)]
pub struct ServiceIdentity {
    identity: &'static str,
    operation: &'static str,
}
impl ServiceIdentity {
    pub fn verified(identity: &'static str, operation: &'static str) -> Self {
        Self {
            identity,
            operation,
        }
    }
}
impl RoutePrincipal for ServiceIdentity {
    fn is_api_key(&self) -> bool {
        false
    }
    fn service_identity(&self) -> Option<&str> {
        Some(self.identity)
    }
    fn has_permission(&self, permission: &str) -> bool {
        self.operation == permission
    }
}
#[derive(Clone)]
struct PrivateListener;
/// Applied only by the private listener constructor, never the public app.
pub fn private_listener<S: Clone + Send + Sync + 'static>(
    router: axum::Router<S>,
) -> axum::Router<S> {
    router.layer(axum::Extension(PrivateListener))
}

pub async fn enforce(
    State(registry): State<Arc<Registry>>,
    request: Request,
    next: Next,
) -> Response {
    let principal = request.extensions().get::<AuthContext>();
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let policy = matched.and_then(|path| registry.policy(request.method(), path));
    let Some(policy) = policy else {
        tracing::error!(method=%request.method(),matched_path=matched,api_key_id=?principal.and_then(|p|p.api_key_id),"route_policy_missing");
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error":"route_policy_missing"})),
        )
            .into_response();
    };
    let allowed = if matches!(
        policy.auth_mode(),
        nanosiem_core::auth::route_policy::AuthMode::ServiceIdentity(_)
    ) {
        request.extensions().get::<PrivateListener>().is_some()
            && policy
                .evaluate(request.extensions().get::<ServiceIdentity>())
                .is_allow()
    } else {
        policy.evaluate(principal).is_allow()
    };
    if !allowed {
        tracing::warn!(method=%request.method(),matched_path=matched,api_key_id=?principal.and_then(|p|p.api_key_id),"route_policy_denied");
        return (
            if principal.is_some() || request.extensions().get::<ServiceIdentity>().is_some() {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            },
            axum::Json(serde_json::json!({"error":"route_policy_denied"})),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[tokio::test]
    async fn registry_http_denies_missing_policy_and_service_on_public_listener() {
        static CALLED: AtomicUsize = AtomicUsize::new(0);
        async fn handler() -> &'static str {
            CALLED.fetch_add(1, Ordering::SeqCst);
            "ok"
        }
        let routes = || {
            Router::new().route(
                "/internal/example/{id}",
                routing::get(handler, RoutePolicy::service("platform", "example:read")),
            )
        };
        let service = ServiceIdentity::verified("platform", "example:read");
        let probe = || {
            Request::builder()
                .uri("/internal/example/one")
                .body(Body::empty())
                .unwrap()
        };
        let public = routes()
            .into_router()
            .layer(axum::Extension(service.clone()));
        assert_eq!(
            public.oneshot(probe()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let private =
            private_listener(routes().into_router()).layer(axum::Extension(service.clone()));
        assert_eq!(
            private.oneshot(probe()).await.unwrap().status(),
            StatusCode::OK
        );
        let mut missing = routes();
        missing.entries.clear();
        let missing = private_listener(missing.into_router()).layer(axum::Extension(service));
        assert_eq!(
            missing.oneshot(probe()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            CALLED.load(Ordering::SeqCst),
            1,
            "missing policy never reaches a handler"
        );
    }
}

/// Configured service credentials are independent of user JWT/API-key auth.
#[derive(Clone)]
struct BearerCredential {
    token: Option<Arc<str>>,
    header: &'static str,
}

// Credential validators are synchronous and bounded: service bearers or HMAC
// principals. User authentication and owner/tenant resolution stay independent.
type ServiceVerifier = Arc<dyn Fn(&axum::http::HeaderMap) -> bool + Send + Sync>;
#[derive(Clone, Default)]
pub struct ServiceAuthenticators(BTreeMap<&'static str, ServiceVerifier>);
impl ServiceAuthenticators {
    pub fn register(
        mut self,
        identity: &'static str,
        verifier: impl Fn(&axum::http::HeaderMap) -> bool + Send + Sync + 'static,
    ) -> Self {
        assert!(
            self.0.insert(identity, Arc::new(verifier)).is_none(),
            "duplicate service identity verifier"
        );
        self
    }
    pub fn bearer(
        self,
        identity: &'static str,
        token: Option<String>,
        header: &'static str,
    ) -> Self {
        let auth = BearerCredential {
            token: token.filter(|s| !s.trim().is_empty()).map(Arc::from),
            header,
        };
        self.register(identity, move |headers| bearer_matches(&auth, headers))
    }
}
fn bearer_matches(auth: &BearerCredential, headers: &axum::http::HeaderMap) -> bool {
    let mut values = headers.get_all(auth.header).iter();
    let provided = values
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    values.next().is_none()
        && match (auth.token.as_deref(), provided) {
            (Some(expected), Some(provided)) if expected.len() == provided.len() => {
                expected
                    .bytes()
                    .zip(provided.bytes())
                    .fold(0u8, |a, (x, y)| a | (x ^ y))
                    == 0
            }
            _ => false,
        }
}
async fn authenticate_registered_service(
    State((registry, authenticators)): State<(Arc<Registry>, ServiceAuthenticators)>,
    mut request: Request,
    next: Next,
) -> Response {
    use nanosiem_core::auth::route_policy::{AuthMode, CapabilityRequirement};
    let policy = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|p| registry.policy(request.method(), p.as_str()));
    let Some(policy) = policy else {
        // The adjacent shared guard owns default deny and its high-signal
        // missing-policy event. It runs before any handler/body work.
        return next.run(request).await;
    };
    let AuthMode::ServiceIdentity(identity) = policy.auth_mode() else {
        // Private liveness is an explicit Public row. Customer modes are never
        // accepted by a service-only listener.
        return if policy.is_public() {
            next.run(request).await
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
    };
    let operation = match policy.capability() {
        CapabilityRequirement::AllOf(ops) if ops.len() == 1 => ops[0],
        _ => return StatusCode::FORBIDDEN.into_response(),
    };
    if !authenticators
        .0
        .get(identity)
        .is_some_and(|verify| verify(request.headers()))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    request
        .extensions_mut()
        .insert(ServiceIdentity::verified(identity, operation));
    next.run(request).await
}
