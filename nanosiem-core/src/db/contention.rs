// SPDX-License-Identifier: AGPL-3.0-or-later

pub const RESOURCE_LOCK_CONTENTION: &str = "RESOURCE_LOCK_CONTENTION";
pub const LOCK_RETRY_AFTER_SECONDS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("RESOURCE_LOCK_CONTENTION: resource is locked; retry shortly")]
pub struct ResourceLockContention;

/// Inspect typed causes before a boundary redacts database diagnostics.
pub fn is_lock_contention(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    for _ in 0..64 {
        let Some(error) = current else { return false };
        if error.is::<ResourceLockContention>() {
            return true;
        }
        if let Some(database) = error.downcast_ref::<sqlx::postgres::PgDatabaseError>() {
            if database.code() == "55P03" {
                return true;
            }
        }
        if let Some(sqlx::Error::Database(database)) = error.downcast_ref::<sqlx::Error>() {
            if database.code().as_deref() == Some("55P03") {
                return true;
            }
        }
        current = error
            .downcast_ref::<std::io::Error>()
            .and_then(|error| {
                error
                    .get_ref()
                    .map(|source| source as &(dyn std::error::Error + 'static))
            })
            .or_else(|| error.source());
    }
    false
}

/// SQLSTATE 40001 (serialization failure) or 40P01 (deadlock victim): the
/// database rolled the whole statement back, so replaying it is safe.
pub fn is_transaction_conflict(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == "40001" || code == "40P01")
}

/// Attempts [`retry_transaction_conflict`] makes in all.
pub const TRANSACTION_CONFLICT_ATTEMPTS: u32 = 3;

/// NAN-3723: run one autocommitted statement, replaying it when the database
/// aborted it as a deadlock or serialization victim. Only for a call that is
/// a single statement on a pool (no caller transaction): the abort rolled it
/// back whole, so the replay is the first attempt again. A concurrent
/// table-lock taker (tenant purge, trigger DDL) then costs a few tens of
/// milliseconds instead of a 503 to the writer that lost the deadlock.
pub async fn retry_transaction_conflict<T, F, Fut>(operation: &'static str, mut call: F) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempt = 1;
    loop {
        match call().await {
            Err(error) if attempt < TRANSACTION_CONFLICT_ATTEMPTS && is_transaction_conflict(&error) => {
                tracing::warn!(
                    operation,
                    attempt,
                    sqlstate = error.as_database_error().and_then(|d| d.code()).as_deref().unwrap_or(""),
                    "statement aborted as a transaction-conflict victim; replaying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(25 * u64::from(attempt))).await;
                attempt += 1;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    #[tokio::test]
    async fn transaction_conflicts_replay_a_bounded_number_of_times() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // A deadlock victim, then success: replayed once.
        let calls = AtomicU32::new(0);
        let result = super::retry_transaction_conflict("test", || async {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 { Err(database_error("40P01")) } else { Ok(7) }
        }).await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Always a serialization failure: gives up after the bound.
        let calls = AtomicU32::new(0);
        let result: Result<(), _> = super::retry_transaction_conflict("test", || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(database_error("40001"))
        }).await;
        assert!(super::is_transaction_conflict(&result.unwrap_err()));
        assert_eq!(calls.load(Ordering::SeqCst), super::TRANSACTION_CONFLICT_ATTEMPTS);
        // Anything else is never replayed.
        for code in ["55P03", "23505", "42501", "XX000"] {
            let calls = AtomicU32::new(0);
            let result: Result<(), _> = super::retry_transaction_conflict("test", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(database_error(code))
            }).await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{code} must not replay");
        }
    }

    #[test]
    fn lock_contention_follows_typed_sources_only() {
        let error = std::io::Error::other(database_error("55P03"));
        assert!(super::is_lock_contention(&error));
        assert!(!super::is_lock_contention(&database_error("XX000")));
        assert!(!super::is_lock_contention(&std::io::Error::other("55P03")));
    }
}
