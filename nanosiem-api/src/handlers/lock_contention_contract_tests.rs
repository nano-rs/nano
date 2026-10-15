// SPDX-License-Identifier: AGPL-3.0-or-later

#[derive(Debug, thiserror::Error)]
#[error("private database diagnostic")]
struct DatabaseFailure(&'static str);
impl sqlx::error::DatabaseError for DatabaseFailure {
    fn message(&self) -> &str {
        "private database diagnostic"
    }
    fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
        Some(self.0.into())
    }
    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }
    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}
pub(crate) fn database_error(code: &'static str) -> sqlx::Error {
    sqlx::Error::Database(Box::new(DatabaseFailure(code)))
}

pub(crate) async fn assert_contention(response: axum::response::Response) {
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(response.headers()["retry-after"], "1");
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let code = body["error"]["code"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .unwrap();
    assert_eq!(code.to_ascii_uppercase(), "RESOURCE_LOCK_CONTENTION");
    assert!(!String::from_utf8_lossy(&bytes).contains("private database diagnostic"));
}
