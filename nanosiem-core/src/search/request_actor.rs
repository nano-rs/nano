// SPDX-License-Identifier: AGPL-3.0-or-later
//! Request-scoped search context that must follow a search into spawned
//! work.
//!
//! `tokio::task_local!` values do NOT cross `tokio::spawn`. Every place the
//! search engine hands a request to a background task (async jobs,
//! streaming, histogram side tasks) wraps the spawned future in [`inherit`],
//! which re-installs inside the new task:
//!
//! - the authenticated member the request runs on behalf of
//!   ([`SEARCH_REQUEST_ACTOR`]),
//! - the denied-source audit scope (NAN-3222), so a source gate that runs
//!   inside a streaming / async task still audits,
//! - the caller's admission wait budget (NAN-4664) and query class
//!   (NAN-4703), so a side task of an agent search admits in the agent class
//!   and waits no longer than its request may,
//! - the current tracing span and subscriber.

use std::future::Future;

use uuid::Uuid;

tokio::task_local! {
    /// The authenticated member on whose behalf the current request runs.
    pub static SEARCH_REQUEST_ACTOR: Uuid;
}

/// Run `future` with `actor` as the request actor.
pub async fn with_request_actor<F: Future>(actor: Uuid, future: F) -> F::Output {
    SEARCH_REQUEST_ACTOR.scope(actor, future).await
}

/// The current request actor, if a scope is active.
pub fn current_request_actor() -> Option<Uuid> {
    SEARCH_REQUEST_ACTOR
        .try_with(|actor| *actor)
        .ok()
        .filter(|actor| !actor.is_nil())
}

/// Wrap a future destined for `tokio::spawn` so it inherits the current
/// request context (a no-op for every piece that is not active).
pub fn inherit<F: Future + Send + 'static>(
    future: F,
) -> std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>>
where
    F::Output: Send + 'static,
{
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> = Box::pin(future);
    // NAN-3222: the denied-source audit scope follows spawned search work.
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> =
        match crate::search::denied_source_audit::current() {
            Some(scope) => Box::pin(crate::search::denied_source_audit::with_scope(scope, future)),
            None => future,
        };
    // NAN-4664: the caller's admission wait budget follows spawned search
    // work (field-stats / histogram side tasks admit there).
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> =
        match crate::search::admission::current_wait_budget() {
            Some(budget) => Box::pin(crate::search::admission::with_wait_budget(budget, future)),
            None => future,
        };
    // NAN-4703: the query class follows too, so a side task of an agent
    // search admits in the agent class.
    let class = crate::search::admission::current_query_class();
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> =
        Box::pin(crate::search::admission::with_query_class(class, future));
    use tracing::instrument::WithSubscriber;
    use tracing::Instrument;
    let future = Box::pin(
        future
            .instrument(tracing::Span::current())
            .with_current_subscriber(),
    );
    match current_request_actor() {
        Some(actor) => Box::pin(SEARCH_REQUEST_ACTOR.scope(actor, future)),
        None => future,
    }
}

#[cfg(test)]
#[path = "request_actor_tests.rs"]
mod tests;
