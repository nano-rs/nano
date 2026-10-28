//! NAN-4193: request ids for background (detection-engine) searches.
//!
//! The lake cell's thread budget (NAN-4174, `nanosiem-lake-worker`
//! `thread_budget::Priority::of_request`) classes a request whose id starts
//! with [`DETECTION_REQUEST_PREFIX`] as background, so a scheduled rule window
//! yields CPU to analyst searches. Only ids this service generates carry the
//! prefix: a caller-supplied `request_id` (cancellation, tuning) is never
//! rewritten to it, and the inputlookup fetch-audit id stays a plain UUID.
//!
//! NAN-4738: an agent-class search (NAN-4703 `QueryClass::Agent`) gets an
//! [`AGENT_REQUEST_PREFIX`] id the same way, so the cell's thread budget runs
//! it below analysts and detections instead of as an interactive statement.
//! [`lake_wire_request_id`] applies the class to every id a classed lake
//! route sends (caller-supplied ones too), so a caller cannot pick its class
//! by naming its own request id.

/// Must match `nanosiem_lake_worker::thread_budget::BACKGROUND_REQUEST_PREFIX`.
pub const DETECTION_REQUEST_PREFIX: &str = "detect-";

/// Must match `nanosiem_lake_worker::thread_budget::AGENT_REQUEST_PREFIX`.
pub const AGENT_REQUEST_PREFIX: &str = "agent-";

tokio::task_local! { static DETECTION_SEARCH: (); }

/// Run `future` so every search it starts without a caller-supplied
/// `request_id` gets a `detect-`-prefixed generated id.
pub async fn with_detection_request_ids<F: std::future::Future>(future: F) -> F::Output {
    DETECTION_SEARCH.scope((), future).await
}

/// The generated query id for a search with no caller-supplied `request_id`.
pub(crate) fn generated_query_id(id: uuid::Uuid) -> String {
    if DETECTION_SEARCH.try_with(|()| ()).is_ok() {
        format!("{DETECTION_REQUEST_PREFIX}{id}")
    } else if crate::search::admission::current_query_class() == crate::search::admission::QueryClass::Agent {
        format!("{AGENT_REQUEST_PREFIX}{id}")
    } else {
        id.to_string()
    }
}

/// The lake worker's request-id cap (`part_query::server`).
const MAX_LAKE_REQUEST_ID_BYTES: usize = 128;

/// NAN-4738: the request id a lake statement carries on the wire, which the
/// cell's thread budget classes the statement by. Every lake route whose
/// statements the cell classes (`/v1/query`, `/v1/query/pages`,
/// `/v1/aggregate/count`) sends its id through here, so the class is set
/// server-side whatever id the statement started with:
///
/// - inside a detection scope ([`with_detection_request_ids`]): unchanged;
/// - in an agent-class request: `agent-`-prefixed, including a
///   caller-supplied `request_id` (otherwise an agent naming its own id ran
///   as an interactive statement) and the plain ids of the field-names and
///   fetch-log routes;
/// - otherwise a caller-supplied id that names the background class
///   (`detect-…`) is moved out of it (`user-detect-…`): only the detection
///   engine runs background statements.
///
/// Deterministic, so a response's binding check and a cold-progress poll
/// use the same id. A prefixed id over the worker's 128-byte cap is
/// replaced by the prefix and a digest of the original id.
pub(crate) fn lake_wire_request_id(id: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if DETECTION_SEARCH.try_with(|()| ()).is_ok() {
        return Cow::Borrowed(id);
    }
    let prefix = if crate::search::admission::current_query_class() == crate::search::admission::QueryClass::Agent {
        if id.starts_with(AGENT_REQUEST_PREFIX) {
            return Cow::Borrowed(id);
        }
        AGENT_REQUEST_PREFIX
    } else if id.starts_with(DETECTION_REQUEST_PREFIX) {
        "user-"
    } else {
        return Cow::Borrowed(id);
    };
    if prefix.len() + id.len() <= MAX_LAKE_REQUEST_ID_BYTES {
        return Cow::Owned(format!("{prefix}{id}"));
    }
    use sha2::{Digest, Sha256};
    Cow::Owned(format!("{prefix}{}", hex::encode(Sha256::digest(id.as_bytes()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prefixes_only_inside_a_detection_scope() {
        let id = uuid::Uuid::now_v7();
        assert_eq!(generated_query_id(id), id.to_string());
        let scoped = with_detection_request_ids(async { generated_query_id(id) }).await;
        assert_eq!(scoped, format!("detect-{id}"));
        // The cell classes `{id}-hist` companions by substring; the prefix
        // must survive derived suffixes and fit the cell's 128-byte cap.
        assert!(format!("{scoped}-count-union-intersection").len() <= 128);
    }

    #[tokio::test]
    async fn agent_class_searches_get_the_agent_prefix() {
        use crate::search::admission::{with_query_class, QueryClass};
        let id = uuid::Uuid::now_v7();
        let agent = with_query_class(QueryClass::Agent, async { generated_query_id(id) }).await;
        assert_eq!(agent, format!("agent-{id}"));
        assert!(format!("{agent}-count-union-intersection").len() <= 128);
        let human = with_query_class(QueryClass::Human, async { generated_query_id(id) }).await;
        assert_eq!(human, id.to_string());
        // A detection scope stays background whatever class it runs under.
        let detection = with_query_class(
            QueryClass::Agent,
            with_detection_request_ids(async { generated_query_id(id) }),
        )
        .await;
        assert_eq!(detection, format!("detect-{id}"));
    }

    /// NAN-4738: the class a lake statement runs in is set server-side,
    /// whatever id the caller sent.
    #[tokio::test]
    async fn lake_wire_ids_carry_the_server_side_class() {
        use crate::search::admission::{with_query_class, QueryClass};
        let agent = |id: &'static str| with_query_class(QueryClass::Agent, async move { lake_wire_request_id(id).into_owned() });
        let human = |id: &'static str| with_query_class(QueryClass::Human, async move { lake_wire_request_id(id).into_owned() });
        // An agent's own request id, or a forged class prefix, stays agent.
        assert_eq!(agent("run-1").await, "agent-run-1");
        assert_eq!(agent("agent-run-1").await, "agent-run-1");
        assert_eq!(agent("detect-run-1").await, "agent-detect-run-1");
        assert_eq!(agent("shared-0123-hist").await, "agent-shared-0123-hist");
        // Humans are unchanged, except a caller id naming the background class.
        assert_eq!(human("run-1").await, "run-1");
        assert_eq!(human("agent-run-1").await, "agent-run-1", "self-demotion only");
        assert_eq!(human("detect-run-1").await, "user-detect-run-1");
        assert_eq!(lake_wire_request_id("detect-run-1"), "user-detect-run-1", "outside any request");
        // The detection engine keeps its background ids in any class.
        let detection = with_query_class(
            QueryClass::Agent,
            with_detection_request_ids(async { lake_wire_request_id("detect-0192").into_owned() }),
        )
        .await;
        assert_eq!(detection, "detect-0192");
        // Over the cell's cap: prefix + digest, deterministic, within 128.
        let long = "x".repeat(125);
        let wire = with_query_class(QueryClass::Agent, async { lake_wire_request_id(&long).into_owned() }).await;
        assert!(wire.starts_with("agent-") && wire.len() <= 128, "{wire}");
        let again = with_query_class(QueryClass::Agent, async { lake_wire_request_id(&long).into_owned() }).await;
        assert_eq!(wire, again);
        assert_eq!(with_query_class(QueryClass::Agent, async { lake_wire_request_id(&"y".repeat(122)).into_owned() }).await.len(), 128);
    }
}
