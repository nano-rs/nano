// SPDX-License-Identifier: AGPL-3.0-or-later
//! The authenticated member a search request runs on behalf of (NAN-2361
//! wave 5). Installed by the search service's auth middleware around each
//! request, read by tenant-scoped data stores that must sign a per-tenant
//! transaction as that member (`TenantLookupStore`).
//!
//! `tokio::task_local!` values do NOT cross `tokio::spawn`. Every place the
//! search engine hands a request to a background task (async jobs,
//! streaming, histogram side tasks) must wrap the spawned future in
//! [`inherit`], which re-installs the current actor inside the new task.
//! A read outside any scope fails closed in the store.

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
    SEARCH_REQUEST_ACTOR.try_with(|actor| *actor).ok().filter(|actor| !actor.is_nil())
}

/// Wrap a future destined for `tokio::spawn` so it inherits the current
/// request actor (a no-op when none is active).
pub fn inherit<F: Future + Send + 'static>(future: F) -> std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>>
where
    F::Output: Send + 'static,
{
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> =
        match crate::inputlookup::shared::fetch_search_id() {
            Some(id) => Box::pin(crate::inputlookup::shared::with_fetch_search_id(id, future)),
            None => Box::pin(future),
        };
    // NAN-3077: opt-in debug evidence follows the request into spawned work.
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> = match crate::search::lake_debug::current() {
        Some(debug) => Box::pin(crate::search::lake_debug::scoped(debug, future)),
        None => Box::pin(future),
    };
    // NAN-3222: the denied-source audit scope follows spawned search work so
    // a gate that runs inside a streaming / async task still audits.
    let future: std::pin::Pin<Box<dyn Future<Output = F::Output> + Send>> =
        match crate::search::denied_source_audit::current() {
            Some(scope) => Box::pin(crate::search::denied_source_audit::with_scope(scope, future)),
            None => future,
        };
    use tracing::Instrument;
    use tracing::instrument::WithSubscriber;
    let future = Box::pin(future.instrument(tracing::Span::current()).with_current_subscriber());
    match current_request_actor() {
        Some(actor) => Box::pin(SEARCH_REQUEST_ACTOR.scope(actor, future)),
        None => future,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawned_tasks_inherit_the_actor_only_through_inherit() {
        let actor = Uuid::new_v4();
        with_request_actor(actor, async move {
            assert_eq!(current_request_actor(), Some(actor));
            let bare = tokio::spawn(async { current_request_actor() }).await.unwrap();
            assert_eq!(bare, None, "task locals never cross tokio::spawn on their own");
            let inherited = tokio::spawn(inherit(async { current_request_actor() })).await.unwrap();
            assert_eq!(inherited, Some(actor));
        })
        .await;
        assert_eq!(current_request_actor(), None);
    }

    #[tokio::test]
    async fn spawned_tasks_inherit_the_audit_search_id_without_leaking_scope() {
        let id = Uuid::new_v4();
        crate::inputlookup::shared::with_fetch_search_id(id, async {
            let bare = tokio::spawn(async { crate::inputlookup::shared::fetch_search_id() })
                .await
                .unwrap();
            assert_eq!(bare, None);
            let inherited = tokio::spawn(inherit(async {
                crate::inputlookup::shared::fetch_search_id()
            }))
            .await
            .unwrap();
            assert_eq!(inherited, Some(id));
        })
        .await;
        assert_eq!(crate::inputlookup::shared::fetch_search_id(), None);
    }

}
