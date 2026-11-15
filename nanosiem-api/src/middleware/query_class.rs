// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5437: classify each authenticated API request's searches as human or
//! agent, exactly as the Search service does (`nanosiem-search`
//! `admission_wait_budget_middleware`).
//!
//! The API process runs nPL itself (rule test, rule test-by-id, dashboard
//! panel queries, pivt / meloD) and is the only process with the outbound
//! `inputlookup` fetcher, so it must see an agent's search as an agent's:
//!
//! - an API key nano Desktop minted for its agents is ALWAYS the agent class,
//!   whatever headers it sends;
//! - any other caller may lower itself to the agent class with
//!   `x-nano-query-class: agent`; a header never raises agent to human.
//!
//! The agent class is the AI-search origin, so every search the request runs
//! is checked by `nanosiem_core::search::ai_command_policy`.

use axum::{extract::Request, middleware::Next, response::Response};
use nanosiem_core::search::admission;

use crate::middleware::AuthContext;

/// Whether this principal is a Desktop agent credential.
pub fn is_agent_credential(auth: &AuthContext) -> bool {
    auth.is_api_key
        && auth
            .api_key_name
            .as_deref()
            .is_some_and(admission::is_agent_api_key_name)
}

/// Layer inside `auth_middleware` (it needs `AuthContext`).
pub async fn query_class_middleware(request: Request, next: Next) -> Response {
    let agent_credential = request
        .extensions()
        .get::<AuthContext>()
        .is_some_and(is_agent_credential);
    let class = admission::resolve_query_class(
        agent_credential,
        request
            .headers()
            .get(admission::QUERY_CLASS_HEADER)
            .and_then(|value| value.to_str().ok()),
    );
    admission::with_query_class(class, next.run(request)).await
}

#[cfg(test)]
#[path = "query_class_tests.rs"]
mod tests;
