//! NAN-4193: request ids for background (detection-engine) searches.
//!
//! The lake cell's thread budget (NAN-4174, `nanosiem-lake-worker`
//! `thread_budget::Priority::of_request`) classes a request whose id starts
//! with [`DETECTION_REQUEST_PREFIX`] as background, so a scheduled rule window
//! yields CPU to analyst searches. Only ids this service generates carry the
//! prefix: a caller-supplied `request_id` (cancellation, tuning) is never
//! rewritten, and the inputlookup fetch-audit id stays a plain UUID.

/// Must match `nanosiem_lake_worker::thread_budget::BACKGROUND_REQUEST_PREFIX`.
pub const DETECTION_REQUEST_PREFIX: &str = "detect-";

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
    } else {
        id.to_string()
    }
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
}
