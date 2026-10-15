// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-side control metadata. This module has no feed artifact client.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Fixture-only instrumentation at actual artifact and reader entry points.
#[cfg(feature = "enrichment-read-audit")]
pub mod audit {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ARTIFACT_READS: AtomicU64 = AtomicU64::new(0);
    static FEED_MATCHES: AtomicU64 = AtomicU64::new(0);
    pub(crate) fn artifact_read() {
        ARTIFACT_READS.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn feed_match() {
        FEED_MATCHES.fetch_add(1, Ordering::Relaxed);
    }
    pub fn counts() -> (u64, u64) {
        (
            ARTIFACT_READS.load(Ordering::Relaxed),
            FEED_MATCHES.load(Ordering::Relaxed),
        )
    }
}

/// The authoritative query is capped at MAX_RIGHTS + 1, so overflow denies all.
pub const MAX_RIGHTS: usize = 64;

static READ_POOL: std::sync::OnceLock<Option<sqlx::PgPool>> = std::sync::OnceLock::new();

fn environment_pool(max_connections: u32) -> Option<sqlx::PgPool> {
    let url = std::env::var("NANO_PLATFORM_READ_DATABASE_URL").ok().or_else(|| {
        tracing::warn!("platform enrichment read database URL missing; denying stored platform enrichment");
        None
    })?;
    let options = crate::db::pooler::options(&url).map_err(|error| {
        tracing::warn!(%error, "invalid platform enrichment read database options; denying stored platform enrichment");
    }).ok()?
        .application_name("nano-platform-read");
    Some(crate::db::connection_budget::pool_options(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect_lazy_with(options))
}

/// Worker startup supplies its lane budget and reuses its metadata pool only
/// when the configured connection identity is identical. Never substitute an
/// unrelated event/storage principal for the execute-only read capability.
pub fn configure_environment_pool(pool: Option<sqlx::PgPool>, max_connections: u32) {
    READ_POOL.get_or_init(|| pool.or_else(|| environment_pool(max_connections.max(1))));
}

/// Deployments with no platform enrichment at all (the open trusted-local
/// cell: platform feeds, their registry and publication are hosted-only
/// schema) deny stored platform enrichment by construction. Record that once
/// instead of the missing-URL warning a misconfigured hosted worker gets.
pub fn disable_environment_pool(reason: &'static str) {
    READ_POOL.get_or_init(|| {
        tracing::info!(reason, "platform enrichment not configured; stored platform enrichment is denied");
        None
    });
}

/// Resolve once at request dispatch. Retry transient connection/query failures
/// in fresh transactions; an empty successful authorization is not a failure.
pub async fn resolve_from_environment(tenant: Uuid) -> ReadAuthorization {
    let pool = READ_POOL.get_or_init(|| environment_pool(4));
    let Some(pool) = pool else {
        return ReadAuthorization::unknown(tenant, Utc::now());
    };
    resolve_from_pool(pool, tenant).await
}

pub async fn resolve_from_pool(pool: &sqlx::PgPool, tenant: Uuid) -> ReadAuthorization {
    let identity = crate::auth::TrustedTenantContext {
        tenant_id: tenant,
        tenant_slug: String::new(),
    };
    // At most three one-second attempts plus 50/100 ms backoff (3.15 s).
    for attempt in 0..3 {
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut tx = pool.begin().await?;
            let authority = ReadAuthorization::try_resolve(&mut tx, &identity).await?;
            tx.commit().await?;
            Ok::<_, sqlx::Error>(authority)
        }).await;
        match result {
            Ok(Ok(authority)) => return authority,
            Ok(Err(error)) => tracing::warn!(%tenant, attempt = attempt + 1, %error,
                "platform enrichment read authorization query failed"),
            Err(error) => tracing::warn!(%tenant, attempt = attempt + 1, %error,
                "platform enrichment read authorization query timed out"),
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(50 << attempt)).await;
        }
    }
    ReadAuthorization::unknown(tenant, Utc::now())
}

/// A result fence is not permission. It can only invalidate frozen output
/// against fresh authority; the enclosing transport/storage authenticates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFence {
    pub tenant_id: Uuid,
    pub authority_sha256: String,
    pub valid_until: Option<DateTime<Utc>>,
}

impl ReadFence {
    pub async fn validate(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &crate::auth::TrustedTenantContext,
    ) -> bool {
        if self.tenant_id != tenant.tenant_id {
            return false;
        }
        let current = ReadAuthorization::resolve(tx, tenant).await;
        self.authority_sha256 == current.cache_identity()
            && self.valid_until.is_none_or(|until| until > Utc::now())
    }
}

tokio::task_local! {
    static RESULT_FENCE: std::sync::Arc<std::sync::Mutex<(Option<ReadFence>, bool)>>;
}

/// Carry the bounded aggregate fence through server-created search tasks.
pub fn inherit_result_fence<F: std::future::Future>(
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    let state = RESULT_FENCE.try_with(Clone::clone).ok();
    async move {
        match state {
            Some(state) => RESULT_FENCE.scope(state, future).await,
            None => future.await,
        }
    }
}

pub fn record_result_fence(fence: Option<ReadFence>) {
    let _ = RESULT_FENCE.try_with(|state| {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(fence) = fence else {
            state.1 = false;
            return;
        };
        if let Some(old) = state.0.as_mut() {
            if old.tenant_id != fence.tenant_id || old.authority_sha256 != fence.authority_sha256 {
                state.1 = false;
            } else {
                old.valid_until = old.valid_until.into_iter().chain(fence.valid_until).min();
            }
        } else {
            state.0 = Some(fence);
        }
    });
}

pub async fn capture_result_fence<T>(
    future: impl std::future::Future<Output = T>,
) -> (T, Option<ReadFence>) {
    RESULT_FENCE
        .scope(
            std::sync::Arc::new(std::sync::Mutex::new((None, true))),
            async {
                let result = future.await;
                let fence = RESULT_FENCE.with(|state| {
                    let state = state.lock().unwrap_or_else(|e| e.into_inner());
                    if state.1 {
                        state.0.clone()
                    } else {
                        None
                    }
                });
                (result, fence)
            },
        )
        .await
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq, Eq)]
pub(crate) struct ReadRight {
    pub feed_id: String,
    pub feed_revision: i64,
    pub tier: String,
    pub grant_revision: i64,
    pub entitlement_revision: i64,
    pub deny_epoch: i64,
    pub valid_until: DateTime<Utc>,
}

impl ReadRight {
    /// `self` (current) still carries `snapshot`'s grant at `at`: the same
    /// grant identity, a data revision no older than the snapshot's, valid.
    fn still_grants(&self, snapshot: &Self, at: DateTime<Utc>) -> bool {
        self.feed_id == snapshot.feed_id
            && self.tier == snapshot.tier
            && self.grant_revision == snapshot.grant_revision
            && self.entitlement_revision == snapshot.entitlement_revision
            && self.deny_epoch == snapshot.deny_epoch
            && self.feed_revision >= snapshot.feed_revision
            && self.valid_until > at
    }
}

/// Server-created authority, deliberately not Deserialize. No event, request
/// body or compiler SQL can construct a permission. No positive metadata cache
/// is retained between requests (bound: zero entries).
#[derive(Debug, Clone, Serialize)]
pub struct ReadAuthorization {
    tenant_id: Uuid,
    evaluated_at: DateTime<Utc>,
    rights: Vec<ReadRight>,
}

impl ReadAuthorization {
    pub fn fence(&self, stamp_expiry: Option<DateTime<Utc>>) -> ReadFence {
        ReadFence {
            tenant_id: self.tenant_id,
            authority_sha256: self.cache_identity(),
            valid_until: self
                .rights
                .iter()
                .map(|r| r.valid_until)
                .chain(stamp_expiry)
                .min(),
        }
    }
    /// Compose permissions already established by the server's resolver.
    /// This is not a wire deserializer and must never receive event metadata.
    pub fn from_resolved(
        tenant: Uuid,
        evaluated_at: DateTime<Utc>,
        revisions: &[super::AuthorizedRevision],
    ) -> Self {
        if revisions.len() > MAX_RIGHTS
            || revisions.iter().any(|r| {
                r.tenant_id != tenant
                    || r.evaluated_at > evaluated_at
                    || !r.reference.valid()
                    || r.deny_epoch < 0
            })
        {
            return Self::unknown(tenant, evaluated_at);
        }
        let mut rights = revisions
            .iter()
            .filter(|r| r.valid_until > evaluated_at)
            .map(|r| ReadRight {
                feed_id: r.reference.feed_id.clone(),
                feed_revision: r.reference.feed_revision,
                tier: r.reference.tier.clone(),
                grant_revision: r.reference.grant_revision,
                entitlement_revision: r.reference.entitlement_revision,
                deny_epoch: r.deny_epoch,
                valid_until: r.valid_until,
            })
            .collect::<Vec<_>>();
        rights.sort_by(|a, b| (&a.feed_id, a.feed_revision).cmp(&(&b.feed_id, b.feed_revision)));
        Self {
            tenant_id: tenant,
            evaluated_at,
            rights,
        }
    }

    pub fn unknown(tenant_id: Uuid, evaluated_at: DateTime<Utc>) -> Self {
        Self {
            tenant_id,
            evaluated_at,
            rights: Vec::new(),
        }
    }

    pub async fn resolve(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &crate::auth::TrustedTenantContext,
    ) -> Self {
        Self::try_resolve(tx, tenant).await
            .unwrap_or_else(|error| {
                tracing::warn!(tenant = %tenant.tenant_id, %error,
                    "platform enrichment read authorization failed; denying stored platform enrichment");
                Self::unknown(tenant.tenant_id, Utc::now())
            })
    }

    async fn try_resolve(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &crate::auth::TrustedTenantContext,
    ) -> Result<Self, sqlx::Error> {
        let evaluated_at = Utc::now();
        let rows = sqlx::query_as::<_, ReadRight>(
            "SELECT feed_id,feed_revision,tier,grant_revision,entitlement_revision,deny_epoch,valid_until FROM nano_shared.platform_enrichment_read_context($1)",
        ).bind(tenant.tenant_id).fetch_all(&mut **tx).await?;
        let rights = if rows.len() <= MAX_RIGHTS { rows } else { Vec::new() };
        Ok(Self { tenant_id: tenant.tenant_id, evaluated_at, rights })
    }

    pub fn evaluated_at(&self) -> DateTime<Utc> {
        self.evaluated_at
    }

    pub fn rights_len(&self) -> usize {
        self.rights.len()
    }

    /// Include this in every cache identity, in addition to the existing
    /// tenant/source/query fences. Evaluation time is checked at return.
    pub fn cache_identity(&self) -> String {
        let bytes =
            serde_json::to_vec(&(self.tenant_id, &self.rights)).expect("bounded control metadata");
        hex::encode(Sha256::digest(bytes))
    }

    /// Fixed worker SQL expression; `record` must be an internally generated
    /// JSON expression, never request SQL. Control values are SQL-escaped.
    pub fn sql_control_metadata(&self) -> String {
        serde_json::to_string(&self.rights).expect("bounded control metadata")
    }

    pub fn permission_sql(&self, record: &str) -> String {
        if self.rights.is_empty() {
            return "0".into();
        }
        let data = format!("JSONExtractRaw({record}, 'data')");
        let right = "__nano_right";
        let premium = format!("((JSONExtractString({right}, 'tier') = 'included' AND JSONExtractString({data}, 'feed_class') = 'baseline' AND JSONExtractString({data}, 'premium', 'tier') = '' AND JSONExtractInt({data}, 'premium', 'grant_revision') = 0 AND JSONExtractInt({data}, 'premium', 'entitlement_revision') = 0) OR (JSONExtractString({data}, 'feed_class') = 'premium' AND JSONExtractString({data}, 'premium', 'tier') = JSONExtractString({right}, 'tier') AND JSONExtractInt({data}, 'premium', 'grant_revision') = JSONExtractInt({right}, 'grant_revision') AND JSONExtractInt({data}, 'premium', 'entitlement_revision') = JSONExtractInt({right}, 'entitlement_revision')))");
        format!("(JSONExtractInt({data}, 'contract_version') = 1 AND JSONExtractString({data}, 'status') IN ('match', 'no_match') AND parseDateTime64BestEffortOrNull(JSONExtractString({data}, 'valid_until'), 6, 'UTC') > fromUnixTimestamp64Micro({now}) AND arrayExists({right} -> JSONExtractString({data}, 'feed_id') = JSONExtractString({right}, 'feed_id') AND JSONExtractString({record}, 'provider') = concat('platform/', JSONExtractString({right}, 'feed_id')) AND JSONExtractInt({data}, 'feed_revision_id') = JSONExtractInt({right}, 'feed_revision') AND parseDateTime64BestEffortOrNull(JSONExtractString({right}, 'valid_until'), 6, 'UTC') > fromUnixTimestamp64Micro({now}) AND {premium}, JSONExtractArrayRaw({{nano_enrichment_authority:String}})))", now=self.evaluated_at.timestamp_micros())
    }

    /// Permission for the physical Array(Tuple(..., data Tuple(...))) lake
    /// schema. The bounded, server-resolved rights become constant keys once
    /// at planning time; no rights JSON or grant timestamps are parsed per row.
    /// Missing tuple members have the same defaults as the JSON reader.
    pub fn tuple_permission_sql(&self, record: &str) -> String {
        let string = |value: &str| format!("unhex('{}')", hex::encode(value));
        let mut keys = Vec::new();
        for right in self.rights.iter().filter(|r| r.valid_until > self.evaluated_at) {
            let feed = string(&right.feed_id);
            if right.tier == "included" {
                keys.push(format!("tuple('baseline', {feed}, toInt64({}), '', toInt64(0), toInt64(0))", right.feed_revision));
            }
            keys.push(format!("tuple('premium', {feed}, toInt64({}), {}, toInt64({}), toInt64({}))",
                right.feed_revision, string(&right.tier), right.grant_revision, right.entitlement_revision));
        }
        if keys.is_empty() {
            return "0".into();
        }
        let data = format!("tupleElement({record}, 'data', tuple())");
        let field = |name: &str, default: &str| format!("ifNull(tupleElement({data}, '{name}', {default}), {default})");
        let premium = format!("tupleElement({data}, 'premium', tuple())");
        let premium_field = |name: &str, default: &str| format!("ifNull(tupleElement({premium}, '{name}', {default}), {default})");
        let key = format!("tuple({}, {}, toInt64({}), {}, toInt64({}), toInt64({}))",
            field("feed_class", "''"), field("feed_id", "''"), field("feed_revision_id", "0"),
            premium_field("tier", "''"), premium_field("grant_revision", "0"), premium_field("entitlement_revision", "0"));
        format!("({} = 1 AND {} IN ('match', 'no_match') AND parseDateTime64BestEffortOrNull({}, 6, 'UTC') > fromUnixTimestamp64Micro({}) AND tupleElement({record}, 'provider', '') = concat('platform/', {}) AND has([{}], {key}))",
            field("contract_version", "0"), field("status", "''"), field("valid_until", "''"),
            self.evaluated_at.timestamp_micros(), field("feed_id", "''"), keys.join(", "))
    }

    /// Aggregates cannot be repaired by masking their returned cells. Reject
    /// the entire derived result if any contributing permission has changed.
    ///
    /// NAN-3293: this is a revocation check, not an identity check. The
    /// snapshot's rights already bounded what the work could read (rows were
    /// masked against them), so the result may return when every snapshot
    /// right is still granted under the same grant: same feed, tier, grant
    /// and entitlement revision and deny epoch, with the feed's data revision
    /// equal or newer and still valid. A routine feed refresh (new data
    /// revision, renewed `valid_until`, new bundle digest) is not a
    /// revocation; the previous exact-identity comparison failed every query
    /// that straddled one (hourly for threatfox/tor on lean cells). Anything
    /// narrower — a dropped feed, a changed tier/grant/entitlement revision,
    /// a raised deny epoch, a data-revision rollback, an expired right or
    /// stamp, an unresolvable (empty) current authority — still refuses.
    pub fn may_return(&self, current: &Self, earliest_stamp_expiry: Option<DateTime<Utc>>) -> bool {
        let returned_at = Utc::now().max(current.evaluated_at);
        // An empty snapshot is a boot/resolver-failure artifact: its fully
        // masked result must not stand once rights exist (no revocation, but
        // returning it would publish under-enriched state as complete).
        let snapshot_unknown_now_granted = self.rights.is_empty() && !current.rights.is_empty();
        self.tenant_id == current.tenant_id
            && current.evaluated_at >= self.evaluated_at
            && !snapshot_unknown_now_granted
            && earliest_stamp_expiry.is_none_or(|t| t > returned_at)
            && self.rights.iter().all(|r| {
                r.valid_until > returned_at
                    && current.rights.iter().any(|c| c.still_grants(r, returned_at))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> ReadAuthorization {
        let now = Utc::now();
        ReadAuthorization {
            tenant_id: Uuid::nil(),
            evaluated_at: now,
            rights: vec![ReadRight {
                feed_id: "feed'\\name".into(), feed_revision: 7, tier: "included".into(),
                grant_revision: 3, entitlement_revision: 4, deny_epoch: 0,
                valid_until: now + chrono::Duration::hours(1),
            }],
        }
    }

    #[test]
    fn tuple_permission_precomputes_bounded_keys_without_json() {
        let sql = authority().tuple_permission_sql("stamp");
        assert!(!sql.contains("JSON"));
        assert!(!sql.contains("arrayExists"));
        assert!(!sql.contains("nano_enrichment_authority"));
        assert_eq!(sql.matches("parseDateTime64BestEffortOrNull").count(), 1);
        assert!(sql.contains("'baseline'"));
        assert!(sql.contains("'premium'"));
        assert!(sql.contains("toInt64(3), toInt64(4)"));
        assert!(sql.contains(&hex::encode("feed'\\name")));
        assert!(!sql.contains("feed'\\name"));
        assert!(sql.contains("'contract_version'"));
        assert!(sql.contains("'status'"));
        assert!(sql.contains("'provider', '') = concat('platform/'"));
    }

    #[test]
    fn tuple_permission_unknown_and_expired_rights_deny_all() {
        let mut authority = authority();
        authority.rights[0].valid_until = authority.evaluated_at;
        assert_eq!(authority.tuple_permission_sql("stamp"), "0");
        assert_eq!(ReadAuthorization::unknown(Uuid::nil(), Utc::now()).tuple_permission_sql("stamp"), "0");
    }

    #[test]
    fn tuple_permission_premium_does_not_grant_baseline() {
        let mut authority = authority();
        authority.rights[0].tier = "paid".into();
        let sql = authority.tuple_permission_sql("stamp");
        assert!(!sql.contains("'baseline'"));
        assert!(sql.contains("'premium'"));
    }

    #[test]
    fn read_control_metadata_preserves_mask_field_names_and_types() {
        let authority = authority();
        let rights: serde_json::Value = serde_json::from_str(&authority.sql_control_metadata()).unwrap();
        assert_eq!(authority.rights_len(), 1);
        assert_eq!(rights[0]["feed_revision"].as_i64(), Some(7));
        assert_eq!(rights[0]["grant_revision"].as_i64(), Some(3));
        assert_eq!(rights[0]["entitlement_revision"].as_i64(), Some(4));
        assert_eq!(rights[0]["tier"], "included");
        assert_eq!(rights[0]["valid_until"].as_str().unwrap().parse::<DateTime<Utc>>().unwrap(), authority.rights[0].valid_until);
        assert!(rights[0].get("feed_revision_id").is_none());
        let unknown = ReadAuthorization::unknown(Uuid::nil(), authority.evaluated_at());
        assert_eq!(unknown.rights_len(), 0);
        assert_eq!(unknown.sql_control_metadata(), "[]");
        assert_eq!(unknown.permission_sql("stamp"), "0");
        assert_eq!(unknown.tuple_permission_sql("stamp"), "0");
    }

    fn resolved_at(at: DateTime<Utc>, rights: Vec<ReadRight>) -> ReadAuthorization {
        ReadAuthorization { tenant_id: Uuid::nil(), evaluated_at: at, rights }
    }

    #[test]
    fn identical_grants_re_resolved_minutes_later_may_return() {
        let snapshot = authority();
        let later = resolved_at(snapshot.evaluated_at + chrono::Duration::minutes(3), snapshot.rights.clone());
        assert!(snapshot.may_return(&later, None));
    }

    /// NAN-3293 live cause: the lean cell's platform-bundle sidecar published
    /// a refreshed bundle mid-job (threatfox/tor_exit_nodes feed revision
    /// +1, renewed valid_until, new bundle digest, policy revision 2 -> 3).
    /// The grant itself was unchanged; the exact cache-identity compare
    /// failed the durable baseline job anyway.
    #[test]
    fn feed_refresh_under_an_unchanged_grant_may_return() {
        let snapshot = authority();
        let mut refreshed = snapshot.rights.clone();
        refreshed[0].feed_revision += 1;
        refreshed[0].valid_until += chrono::Duration::hours(1);
        let later = resolved_at(snapshot.evaluated_at + chrono::Duration::minutes(3), refreshed);
        assert_ne!(snapshot.cache_identity(), later.cache_identity());
        assert!(snapshot.may_return(&later, None));
        // A widened grant set (a feed newly granted) is not a revocation.
        let mut widened = later.clone();
        widened.rights.push(ReadRight { feed_id: "threatfox".into(), ..snapshot.rights[0].clone() });
        assert!(snapshot.may_return(&widened, None));
    }

    #[test]
    fn narrowed_grants_refuse_return() {
        let snapshot = authority();
        let later_at = snapshot.evaluated_at + chrono::Duration::minutes(3);
        let narrowed = |change: &dyn Fn(&mut ReadRight)| {
            let mut rights = snapshot.rights.clone();
            change(&mut rights[0]);
            resolved_at(later_at, rights)
        };
        assert!(!snapshot.may_return(&resolved_at(later_at, Vec::new()), None), "feed dropped");
        assert!(!snapshot.may_return(&ReadAuthorization::unknown(Uuid::nil(), later_at), None), "unresolvable");
        assert!(!snapshot.may_return(&narrowed(&|r| r.deny_epoch += 1), None), "deny epoch");
        assert!(!snapshot.may_return(&narrowed(&|r| r.tier = "paid".into()), None), "tier");
        assert!(!snapshot.may_return(&narrowed(&|r| r.grant_revision += 1), None), "grant revision");
        assert!(!snapshot.may_return(&narrowed(&|r| r.entitlement_revision += 1), None), "entitlement revision");
        assert!(!snapshot.may_return(&narrowed(&|r| r.feed_revision -= 1), None), "data revision rollback");
        assert!(!snapshot.may_return(&narrowed(&|r| r.feed_id = "other".into()), None), "other feed");
        assert!(!snapshot.may_return(&narrowed(&|r| r.valid_until = later_at), None), "expired at return");
        let mut foreign = snapshot.clone();
        foreign.tenant_id = Uuid::new_v4();
        assert!(!snapshot.may_return(&foreign, None), "tenant");
        assert!(!snapshot.may_return(&resolved_at(snapshot.evaluated_at - chrono::Duration::seconds(1), snapshot.rights.clone()), None),
            "metadata older than the snapshot");
        assert!(!snapshot.may_return(&snapshot, Some(snapshot.evaluated_at)), "stamp expired");
    }

    #[test]
    fn empty_snapshot_does_not_return_once_rights_exist() {
        let granted = authority();
        let unknown = ReadAuthorization::unknown(Uuid::nil(), granted.evaluated_at - chrono::Duration::minutes(1));
        assert!(!unknown.may_return(&granted, None));
        assert!(unknown.may_return(&ReadAuthorization::unknown(Uuid::nil(), granted.evaluated_at), None));
    }

    #[tokio::test]
    async fn read_pool_failure_still_denies_all() {
        // A lazy, closed pool cannot touch a database, and fails all retries.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@127.0.0.1/fixture").unwrap();
        pool.close().await;
        let tenant = Uuid::new_v4();
        let authority = resolve_from_pool(&pool, tenant).await;
        assert_eq!(authority.rights_len(), 0);
        assert_eq!(authority.tenant_id, tenant);
        assert_eq!(authority.permission_sql("stamp"), "0");
        assert_eq!(authority.tuple_permission_sql("stamp"), "0");
    }
}
