// SPDX-License-Identifier: AGPL-3.0-or-later
//! Existing demo signals, shared by automation and alert-channel send boundaries.
#[cfg(feature = "enterprise")]
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub const SUPPRESSED_DEMO: &str = "suppressed_demo";

/// The existing deployment mode, never a separate mail/demo override.
pub fn legacy_demo() -> bool {
    match std::env::var("DEPLOYMENT_MODE") {
        Ok(mode) => mode.eq_ignore_ascii_case("demo"),
        Err(std::env::VarError::NotPresent) => false,
        Err(_) => true,
    }
}

/// The same tenant fence is taken exclusively by the demo-flag trigger.
/// Transactions only admit bounded IO leases; none is retained during IO.
#[cfg(feature = "enterprise")]
pub async fn tenant_demo(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
) -> Result<bool, sqlx::Error> {
    hold_tenant_fence(tx, tenant).await?;
    let demo: Option<bool> = sqlx::query_scalar("SELECT CASE WHEN nano_shared.current_tenant_id()=$1 THEN COALESCE((SELECT demo FROM public.tenant_demo_settings WHERE tenant_id=$1),FALSE) ELSE NULL END")
        .bind(tenant).fetch_one(&mut **tx).await?;
    demo.ok_or_else(|| sqlx::Error::Protocol("demo tenant context unavailable".into()))
}

/// Acquire this before any SOAR row lock, including receipt-only writes.
/// The flag writer takes the exclusive fence before touching those rows.
#[cfg(feature = "enterprise")]
pub async fn hold_tenant_fence(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,4483))")
        .bind(tenant.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Committed notification admission. This contains no connection or transaction.
/// The database lease lasts 60 seconds; the entire attempt must finish within
/// 45 seconds of starting admission, leaving room for commit and settlement.
#[cfg(feature = "enterprise")]
pub struct NotificationSendLease {
    id: Uuid,
    tenant: Uuid,
    deadline: tokio::time::Instant,
}

#[cfg(feature = "enterprise")]
impl NotificationSendLease {
    pub async fn admit(
        mut tx: Transaction<'_, Postgres>,
        tenant: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
        if legacy_demo() || tenant_demo(&mut tx, tenant).await? {
            tx.rollback().await?;
            return Ok(None);
        }
        let id = Uuid::now_v7();
        let admitted: bool =
            sqlx::query_scalar("SELECT nano_shared.notification_send_lease('claim',$1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if !admitted {
            return Err(sqlx::Error::Protocol(
                "notification send admission unavailable".into(),
            ));
        }
        // Owning the transaction makes returning a lease before commit impossible.
        tx.commit().await?;
        Ok(Some(Self {
            id,
            tenant,
            deadline,
        }))
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn tenant(&self) -> Uuid {
        self.tenant
    }

    pub async fn run<F: std::future::Future>(self, send: F) -> Option<F::Output> {
        // timeout_at may poll once at an elapsed deadline. Refuse explicitly
        // so a delayed caller cannot start an expired outbound attempt.
        if tokio::time::Instant::now() >= self.deadline {
            return None;
        }
        tokio::time::timeout_at(self.deadline, send).await.ok()
    }

    pub async fn settle(mut tx: Transaction<'_, Postgres>, id: Uuid) -> Result<bool, sqlx::Error> {
        let removed: bool =
            sqlx::query_scalar("SELECT nano_shared.notification_send_lease('settle',$1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(removed)
    }
}

/// Explicit GET allowlist; every current/future write and unclassified route
/// under the prefix is closed. HEAD/OPTIONS do not expand the public contract.
pub fn soar_read_path(method: &str, path: &str) -> Option<bool> {
    let path = path.trim_end_matches('/');
    let tail = path.strip_prefix("/api/soar")?;
    if !tail.is_empty() && !tail.starts_with('/') {
        return None;
    }
    let parts: Vec<_> = tail.trim_start_matches('/').split('/').collect();
    let visible = method == "GET"
        && match parts.as_slice() {
            ["packs", "apply-all-upstream-updates"] => false,
            ["flows" | "runs" | "packs"] | ["packs", _] | ["flows", "stats"] | ["runs", "volume"] => true,
            ["flows" | "runs", id] => Uuid::parse_str(id).is_ok(),
            _ => false,
        };
    Some(visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "enterprise")]
    #[tokio::test(start_paused = true)]
    async fn notification_attempt_deadline_cancels_io_and_never_starts_expired_io() {
        let expired = NotificationSendLease {
            id: Uuid::now_v7(),
            tenant: Uuid::now_v7(),
            deadline: tokio::time::Instant::now(),
        };
        let mut sent = false;
        assert!(expired
            .run(async {
                sent = true;
            })
            .await
            .is_none());
        assert!(!sent);
        let start = tokio::time::Instant::now();
        let lease = NotificationSendLease {
            id: Uuid::now_v7(),
            tenant: Uuid::now_v7(),
            deadline: start + std::time::Duration::from_secs(45),
        };
        assert!(lease.run(std::future::pending::<()>()).await.is_none());
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(45));
    }
    #[test]
    fn demo_soar_prefix_is_closed_except_classified_gets() {
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            for path in [
                "/api/soar",
                "/api/soar/flows",
                "/api/soar/flows/x/run",
                "/api/soar/new/future/route",
            ] {
                assert_eq!(soar_read_path(method, path), Some(false));
            }
        }
        for path in [
            "/api/soar/settings",
            "/api/soar/recipients",
            "/api/soar/connections/x",
            "/api/soar/approvals",
            "/api/soar/mail-transport",
            "/api/soar/future",
        ] {
            assert_eq!(soar_read_path("GET", path), Some(false));
        }
        for path in [
            "/api/soar/flows",
            "/api/soar/flows/11111111-1111-4111-8111-111111111111",
            "/api/soar/runs/11111111-1111-4111-8111-111111111111",
            "/api/soar/runs/volume",
            "/api/soar/packs/x",
        ] {
            assert_eq!(soar_read_path("GET", path), Some(true));
        }
        assert_eq!(soar_read_path("GET", "/api/soaring"), None);
    }
}
