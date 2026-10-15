// SPDX-License-Identifier: AGPL-3.0-or-later
//! One tenant per isolated lake job process, one commit in flight. PG leases
//! fence planning/acknowledgment; PG pending manifests survive pod replacement.
//! The catalog checkpoint fences ambiguous REST successes before the PG ack.
use super::{
    customer::CustomerExportTarget, egress::ExportEgress, schema::SchemaContract, ExportTable,
    ExportTarget, RestIcebergCommitter,
};
use crate::{
    iceberg::{CatalogConfig, OCSF_VERSION},
    part_ingest::{
        cell::trusted_from,
        export::{plan_export_reconciled, ExportManifest, ExportState, IcebergCommitter},
        s3_store::{S3Location, S3ObjectStore},
    },
    parts::{
        levels::MergePolicy,
        part_log::{load_log, PartRef},
    },
};
use anyhow::{ensure, Context, Result};
use chrono::Utc;
use nanosiem_core::{
    crypto::EncryptionService,
    iceberg_export::{self as core, CustomerExportConfig},
    tenant_db::TenantDbContextSigner,
};
use nanosiem_lake_cell::contract::PartSigning;
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    path::Path,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    tenant_id: Uuid,
    /// Provisioned active tenant service member for signed shared transactions.
    actor_id: Uuid,
    source: S3Location,
    signing: PartSigning,
}
struct Database {
    pool: PgPool,
    signer: Option<TenantDbContextSigner>,
    tenant: Uuid,
    actor: Uuid,
}
impl Database {
    async fn begin(&self) -> Result<Transaction<'_, Postgres>> {
        match &self.signer {
            Some(signer) => Ok(signer
                .begin_transaction(&self.pool, self.tenant, self.actor)
                .await?),
            None => Ok(self.pool.begin().await?),
        }
    }
}
struct Claim {
    owner: Uuid,
    generation: i64,
    revision: i64,
    config: CustomerExportConfig,
    credentials: std::collections::HashMap<String, String>,
    state: ExportState,
    pending: Option<ExportManifest>,
}
async fn claim(db: &Database, cipher: &EncryptionService) -> Result<Option<Claim>> {
    if !core::feature_enabled() {
        return Ok(None);
    }
    let owner = Uuid::new_v4();
    let mut tx = db.begin().await?;
    let row=sqlx::query("UPDATE iceberg_export_settings SET lease_owner=$2,lease_until=now()+interval '15 minutes',lease_generation=lease_generation+1 WHERE tenant_id=$1 AND enabled AND next_run_at<=now() AND (lease_until IS NULL OR lease_until<now()) RETURNING *")
        .bind(db.tenant).bind(owner).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let config: CustomerExportConfig = serde_json::from_value(row.try_get("customer_config")?)?;
    config.validate(db.tenant)?;
    let credentials = core::open(
        cipher,
        db.tenant,
        &row.try_get::<Vec<u8>, _>("credentials_encrypted")?,
        &row.try_get::<String, _>("credentials_nonce")?,
    )?;
    let result = Claim {
        owner,
        generation: row.try_get("lease_generation")?,
        revision: row.try_get("revision")?,
        config,
        credentials,
        state: serde_json::from_value(row.try_get("export_state")?)?,
        pending: row
            .try_get::<Option<serde_json::Value>, _>("pending_manifest")?
            .map(serde_json::from_value)
            .transpose()?,
    };
    tx.commit().await?;
    Ok(Some(result))
}
#[derive(Debug, thiserror::Error)]
#[error("export {0} failure")]
struct Failure(&'static str);
fn classified(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<Failure>()
        .map(|e| e.0)
        .unwrap_or("storage")
}

fn backoff_seconds(failures: i32) -> i64 {
    (60_i64 << failures.clamp(0, 6)).min(3600)
}
async fn save_plan(
    db: &Database,
    claim: &Claim,
    state: &ExportState,
    manifest: &ExportManifest,
) -> Result<()> {
    let mut tx = db.begin().await?;
    let result=sqlx::query("UPDATE iceberg_export_settings SET export_state=$5,pending_manifest=$6 WHERE tenant_id=$1 AND lease_owner=$2 AND lease_generation=$3 AND revision=$4 AND enabled AND lease_until>now() AND pending_manifest IS NULL")
        .bind(db.tenant).bind(claim.owner).bind(claim.generation).bind(claim.revision).bind(serde_json::to_value(state)?).bind(serde_json::to_value(manifest)?).execute(&mut *tx).await?;
    ensure!(result.rows_affected() == 1, "export plan lease lost");
    tx.commit().await?;
    Ok(())
}
async fn finish(
    db: &Database,
    claim: &Claim,
    success: bool,
    bytes: u64,
    files: u64,
    lag: i64,
    error_class: &str,
) -> Result<()> {
    let mut tx = db.begin().await?;
    let failures:Option<i32>=sqlx::query_scalar("SELECT failures FROM iceberg_export_settings WHERE tenant_id=$1 AND lease_owner=$2 AND lease_generation=$3 AND revision=$4 AND lease_until>now() FOR UPDATE")
        .bind(db.tenant).bind(claim.owner).bind(claim.generation).bind(claim.revision).fetch_optional(&mut *tx).await?;
    let failures = failures.context("export completion lease lost")?;
    let delay = if success && lag == 0 {
        3600
    } else if success {
        0
    } else {
        backoff_seconds(failures)
    };
    sqlx::query("UPDATE iceberg_export_settings SET lease_owner=NULL,lease_until=NULL,next_run_at=now()+make_interval(secs=>$5),failures=CASE WHEN $6 THEN 0 ELSE failures+1 END,last_success=CASE WHEN $6 THEN now() ELSE last_success END,pending_manifest=CASE WHEN $6 THEN NULL ELSE pending_manifest END,bytes_copied=bytes_copied+$7,files=files+$8,lag_hours=$9,errors=CASE WHEN $6 THEN errors ELSE jsonb_set(errors,ARRAY[$10],to_jsonb(COALESCE((errors->>$10)::bigint,0)+1)) END WHERE tenant_id=$1 AND lease_owner=$2 AND lease_generation=$3 AND revision=$4")
        .bind(db.tenant).bind(claim.owner).bind(claim.generation).bind(claim.revision).bind(delay as f64).bind(success).bind(i64::try_from(bytes)?).bind(i64::try_from(files)?).bind(lag).bind(error_class).execute(&mut *tx).await?;
    tx.commit().await?;
    tracing::info!(tenant_id=%db.tenant,success,bytes_copied=bytes,files,lag_hours=lag,error_class,"customer Iceberg export health");
    Ok(())
}
/// Keep hours sharing either old or new day files in one atomic delta.
/// Splitting these groups could temporarily double-count a replacement day
/// or remove a file still needed by the unselected hours.
fn bounded_plan(
    pending: Vec<(super::super::export::ExportHour, Vec<PartRef>)>,
    state: &ExportState,
) -> Vec<(super::super::export::ExportHour, Vec<PartRef>)> {
    fn root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            parents[index] = parents[parents[index]];
            index = parents[index];
        }
        index
    }
    let mut parents = (0..pending.len()).collect::<Vec<_>>();
    let mut owners = std::collections::BTreeMap::new();
    for (index, (hour, parts)) in pending.iter().enumerate() {
        for id in parts.iter().map(|p| p.part_id.to_string()).chain(
            state
                .exported
                .get(&hour.event_hour)
                .into_iter()
                .flatten()
                .cloned(),
        ) {
            if let Some(previous) = owners.insert(id, index) {
                let a = root(&mut parents, previous);
                let b = root(&mut parents, index);
                parents[a.max(b)] = a.min(b);
            }
        }
    }
    let mut groups = std::collections::BTreeMap::<usize, Vec<_>>::new();
    for (index, item) in pending.into_iter().enumerate() {
        groups
            .entry(root(&mut parents, index))
            .or_default()
            .push(item);
    }
    let mut selected = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut bytes = 0u64;
    for group in groups.into_values() {
        let mut group_ids = std::collections::BTreeSet::new();
        let extra = group
            .iter()
            .flat_map(|(_, parts)| parts)
            .filter(|p| !ids.contains(&p.part_id) && group_ids.insert(p.part_id.clone()))
            .map(|p| p.data_bytes)
            .fold(0u64, u64::saturating_add);
        if !selected.is_empty()
            && (selected.len() + group.len() > 64
                || bytes.saturating_add(extra) > 2 * 1024 * 1024 * 1024)
        {
            break;
        }
        bytes = bytes.saturating_add(extra);
        ids.extend(group_ids);
        selected.extend(group);
    }
    selected.sort_by_key(|(hour, _)| hour.event_hour);
    selected
}

async fn attempt(
    db: &Database,
    claim: &mut Claim,
    bootstrap: &Bootstrap,
) -> Result<(u64, u64, i64)> {
    let source = Arc::new(S3ObjectStore::new(&bootstrap.source)?);
    let live = load_log(source.as_ref(), &db.tenant.to_string())
        .await
        .map_err(|_| Failure("source"))?;
    let parts = live.parts().cloned().collect::<Vec<_>>();
    ensure!(
        parts.len() <= 100_000,
        "export inventory file bound exceeded"
    );
    let arrow = live
        .schema()
        .context("export source has no committed schema")?
        .to_arrow()?;
    let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow)?;
    let now = Utc::now().timestamp_millis();
    let new_plan = claim.pending.is_none();
    if new_plan {
        let pending = bounded_plan(
            plan_export_reconciled(&parts, &claim.state, now, &MergePolicy::default()),
            &claim.state,
        );
        if pending.is_empty() {
            return Ok((0, 0, 0));
        }
        let directory = tempfile::tempdir()?;
        let path = claim.state.record_durable_plan(
            directory.path(),
            &db.tenant.to_string(),
            &pending,
            now.max(claim.state.last_plan_ms + 1),
        )?;
        let manifest = serde_json::from_slice(&std::fs::read(path)?)?;
        claim.pending = Some(manifest);
    }
    let manifest = claim.pending.as_ref().unwrap();
    let location = format!(
        "s3://{}/{}events_v1",
        claim.config.bucket, claim.config.prefix
    );
    let data_prefix = format!("{location}/data/");
    let destination = S3Location {
        endpoint: claim.config.bucket_endpoint.clone(),
        region: claim.config.region.clone(),
        bucket: claim.config.bucket.clone(),
        prefix: format!("{}events_v1/data/", claim.config.prefix),
        access_key_id: claim.credentials["access_key_id"].clone(),
        secret_access_key: claim.credentials["secret_access_key"].clone(),
        session_token: claim.credentials.get("session_token").cloned(),
    };
    let target = Arc::new(CustomerExportTarget::new(
        db.tenant.to_string(),
        source,
        Arc::new(S3ObjectStore::new(&destination)?),
        trusted_from(&bootstrap.signing)?,
        data_prefix.clone(),
    )?);
    // The existing catalog seam accepts projected bearer-token files. This
    // transient owner-only file is removed when the bounded attempt ends;
    // long-lived storage stays in the tenant-bound AES-GCM envelope.
    let mut bearer = None;
    if claim.config.catalog_authentication == core::CatalogAuthentication::Bearer {
        use std::io::Write;
        let token = &claim.credentials["catalog_credential"];
        ensure!(
            (32..=4096).contains(&token.len()),
            "invalid export bearer token length"
        );
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(token.as_bytes())?;
        file.flush()?;
        bearer = Some(file);
    }
    let config = CatalogConfig {
        uri: claim.config.catalog_uri.clone(),
        warehouse: claim.config.warehouse.clone(),
        credential: bearer
            .is_none()
            .then(|| claim.credentials["catalog_credential"].clone()),
        token_file: bearer.as_ref().map(|file| file.path().to_owned()),
        oauth_scope: claim.config.oauth_scope.clone(),
        oauth_audience: claim.config.oauth_audience.clone(),
        oauth_server_uri: claim.config.oauth_server_uri.clone(),
        realm: None,
        allow_anonymous: false,
        s3_endpoint: destination.endpoint,
        s3_region: destination.region,
        s3_access_key: destination.access_key_id,
        s3_secret_key: destination.secret_access_key,
        s3_session_token: destination.session_token,
        s3_path_style_access: true,
        s3_default_credentials: false,
        vended_credentials: false,
    };
    if new_plan {
        // Take custody before publishing a durable plan: queued files and
        // their signed proof must survive source supersession/erasure GC.
        target
            .prepare(manifest, &schema)
            .await
            .map_err(|_| Failure("copy"))?;
        save_plan(db, claim, &claim.state, manifest).await?;
    }
    let table = ExportTable {
        tenant_id: db.tenant.to_string(),
        namespace: claim.config.namespace.clone(),
        dataset: "events".into(),
        location,
        data_prefix,
        contract: SchemaContract {
            version: 1,
            ocsf_version: OCSF_VERSION.into(),
            schema,
        },
        max_files: 100_000,
    };
    let committer = RestIcebergCommitter::new(config, table, target.clone())?;
    committer
        .commit(manifest)
        .await
        .map_err(|_| Failure("catalog"))?;
    // Lag is oldest changed sealed event-hour after the acknowledged plan.
    let remaining = plan_export_reconciled(&parts, &claim.state, now, &MergePolicy::default());
    let lag = remaining
        .iter()
        .map(|(h, _)| now / 3_600_000 - i64::from(h.event_hour) - 1)
        .max()
        .unwrap_or(0)
        .max(0);
    Ok((
        target.bytes_copied.load(Ordering::Relaxed),
        target.files_copied.load(Ordering::Relaxed),
        lag,
    ))
}

fn load_bootstrap(path: &Path) -> Result<Bootstrap> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && metadata.is_file()
            && metadata.len() <= 65536
            && metadata.permissions().mode() & 0o077 == 0,
        "export bootstrap must be a private bounded regular file"
    );
    let bootstrap: Bootstrap = serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("invalid export bootstrap"))?;
    ensure!(
        !bootstrap.tenant_id.is_nil()
            && !bootstrap.actor_id.is_nil()
            && bootstrap.source.prefix.is_empty(),
        "invalid export bootstrap binding"
    );
    core::endpoint(&bootstrap.source.endpoint)?;
    trusted_from(&bootstrap.signing)?;
    Ok(bootstrap)
}

/// Dedicated process mode of the existing job runner. Off means no DB, source,
/// credential, or catalog IO at all. Failures never propagate to serving jobs.
pub async fn run_from_env() -> Result<()> {
    if !core::feature_enabled() {
        return Ok(());
    }
    let path =
        std::env::var("NANO_ICEBERG_EXPORT_BOOTSTRAP_FILE").context("export bootstrap required")?;
    let bootstrap = load_bootstrap(Path::new(&path))?;
    let shared = std::env::var("DEPLOYMENT_MODE").is_ok_and(|v| v == "enterprise_shared");
    if shared {
        ensure!(
            bootstrap.source.bucket == format!("nano-shared-r2-{}", bootstrap.tenant_id),
            "export source bucket must belong to tenant"
        );
    } else {
        ensure!(
            bootstrap.tenant_id.to_string() == "00000000-0000-0000-0000-000000000100",
            "dedicated export uses compatibility tenant"
        );
    }
    let url = std::env::var(if shared {
        "NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL"
    } else {
        "DATABASE_URL"
    })
    .context("export runtime database required")?;
    let pool = nanosiem_core::db::pooler::connect_lazy(
        nanosiem_core::db::connection_budget::pool_options(2),
        &url,
    )?;
    let signer = if shared {
        let database = std::env::var("NANOSIEM_SHARED_RLS_DATABASE")?;
        let role = std::env::var("NANOSIEM_SHARED_RLS_RUNTIME_ROLE")?;
        let (actual_role, actual_db): (String, String) =
            sqlx::query_as("SELECT current_user::text,current_database()::text")
                .fetch_one(&pool)
                .await?;
        ensure!(
            actual_role == role && actual_db == database,
            "export runtime database identity differs"
        );
        let material = nanosiem_core::rls_context_key_env::RlsContextKeyMaterial::from_env()?;
        material.spawn_expiry_monitor("lake-iceberg-export");
        Some(material.into_signer(database, role, 30)?)
    } else {
        None
    };
    let db = Database {
        pool,
        signer,
        tenant: bootstrap.tenant_id,
        actor: bootstrap.actor_id,
    };
    let cipher = EncryptionService::from_env();
    let once = std::env::args().any(|arg| arg == "--once");
    let mut egress = None;
    loop {
        match claim(&db, &cipher).await {
            Ok(Some(mut claim)) => {
                if egress.is_none() {
                    let mut origins = vec![
                        claim.config.catalog_uri.clone(),
                        claim.config.bucket_endpoint.clone(),
                        bootstrap.source.endpoint.clone(),
                    ];
                    if let Some(uri) = &claim.config.oauth_server_uri {
                        origins.push(uri.clone());
                    }
                    let guard = ExportEgress::start(&origins).await?;
                    guard.install_process_proxy();
                    egress = Some(guard);
                }
                let refreshed = load_bootstrap(Path::new(&path))?;
                ensure!(
                    refreshed.tenant_id == bootstrap.tenant_id
                        && refreshed.actor_id == bootstrap.actor_id
                        && refreshed.source.bucket == bootstrap.source.bucket
                        && refreshed.source.endpoint == bootstrap.source.endpoint
                        && refreshed.source.region == bootstrap.source.region,
                    "export source topology changed; restart required"
                );
                match tokio::time::timeout(
                    Duration::from_secs(600),
                    attempt(&db, &mut claim, &refreshed),
                )
                .await
                {
                    Ok(Ok((bytes, files, lag))) => {
                        if finish(&db, &claim, true, bytes, files, lag, "none")
                            .await
                            .is_err()
                        {
                            tracing::warn!("export acknowledgement deferred");
                        }
                    }
                    outcome => {
                        let error_class = match &outcome {
                            Ok(Err(error)) => classified(error),
                            _ => "timeout",
                        };
                        let lag = claim
                            .pending
                            .as_ref()
                            .map(|m| {
                                m.hours
                                    .iter()
                                    .map(|h| {
                                        Utc::now().timestamp_millis() / 3_600_000
                                            - i64::from(h.event_hour)
                                            - 1
                                    })
                                    .max()
                                    .unwrap_or(0)
                                    .max(0)
                            })
                            .unwrap_or(0);
                        if finish(&db, &claim, false, 0, 0, lag, error_class)
                            .await
                            .is_err()
                        {
                            tracing::warn!("export failure acknowledgement deferred");
                        }
                        tracing::warn!(
                            error_class,
                            "customer export failed; pending plan retained"
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(_) => tracing::warn!(error_class = "storage", "customer export claim unavailable"),
        }
        if once {
            return Ok(());
        }
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(60))=>{}, _=tokio::signal::ctrl_c()=>return Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backfill_keeps_complete_hours_and_deduplicates_shared_day_files() {
        use crate::part_ingest::export::ExportHour;
        use crate::parts::{format::PartId, levels::Level};
        let part = PartRef {
            part_id: PartId::new(1).unwrap(),
            level: Level::Day,
            event_hour: 24,
            event_day: Some(1),
            rows: 1,
            min_time_us: 1,
            max_time_us: 1,
            schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64),
            sorted: true,
            data_bytes: 1024 * 1024 * 1024,
            row_groups: 1,
            data_files: 1,
        };
        let shared = (24..48)
            .map(|event_hour| {
                (
                    ExportHour {
                        event_hour,
                        parts: vec![part.part_id.to_string()],
                    },
                    vec![part.clone()],
                )
            })
            .collect();
        assert_eq!(bounded_plan(shared, &ExportState::default()).len(), 24);
        let removals = (0..100)
            .map(|event_hour| {
                (
                    ExportHour {
                        event_hour,
                        parts: vec![],
                    },
                    vec![],
                )
            })
            .collect();
        assert_eq!(bounded_plan(removals, &ExportState::default()).len(), 64);
        let mut pending = (0..60)
            .map(|event_hour| {
                (
                    ExportHour {
                        event_hour,
                        parts: vec![],
                    },
                    vec![],
                )
            })
            .collect::<Vec<_>>();
        pending.extend((60..84).map(|event_hour| {
            (
                ExportHour {
                    event_hour,
                    parts: vec![part.part_id.to_string()],
                },
                vec![part.clone()],
            )
        }));
        assert_eq!(
            bounded_plan(pending, &ExportState::default()).len(),
            60,
            "batch must never split a shared day file"
        );
        let old = ExportState {
            exported: (60..84)
                .map(|hour| (hour, vec![part.part_id.to_string()]))
                .collect(),
            last_plan_ms: 1,
        };
        let pending = (0..84)
            .map(|event_hour| {
                (
                    ExportHour {
                        event_hour,
                        parts: vec![],
                    },
                    vec![],
                )
            })
            .collect();
        assert_eq!(
            bounded_plan(pending, &old).len(),
            60,
            "erasure must not split an old day file"
        );
        let mut larger = part.clone();
        larger.part_id = PartId::new(2).unwrap();
        larger.data_bytes = 3 * 1024 * 1024 * 1024;
        let first = vec![part, larger];
        let result = bounded_plan(
            vec![
                (
                    ExportHour {
                        event_hour: 24,
                        parts: vec![],
                    },
                    first.clone(),
                ),
                (
                    ExportHour {
                        event_hour: 25,
                        parts: vec![],
                    },
                    vec![],
                ),
            ],
            &ExportState::default(),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, first);
    }
    #[test]
    fn retry_backoff_is_bounded_and_monotonic() {
        assert_eq!(backoff_seconds(0), 60);
        assert_eq!(backoff_seconds(1), 120);
        assert_eq!(backoff_seconds(100), 3600);
    }
}

#[cfg(test)]
mod pg_tests {
    use super::*;
    #[derive(Deserialize)]
    struct Auth {
        pg_url: String,
    }
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL fixture"]
    async fn pg_queue_claim_fence_restart_and_health() {
        let path = std::env::var("NANO_EXPORT_TEST_AUTH_FILE").unwrap();
        let auth: Auth = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&auth.pg_url)
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS tenants(id uuid PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../../migrations/postgres/347_lean_iceberg_export.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants VALUES($1),($2)")
            .bind(tenant)
            .bind(other)
            .execute(&pool)
            .await
            .unwrap();
        let cipher = EncryptionService::new(&[8; 32]);
        let config = CustomerExportConfig {
            catalog_uri: "https://catalog.example".into(),
            catalog_authentication: core::CatalogAuthentication::Oauth,
            warehouse: "warehouse".into(),
            namespace: "nano".into(),
            bucket_endpoint: "https://bucket.example".into(),
            bucket: "customer-bucket".into(),
            region: "us-east-1".into(),
            prefix: format!("export/tenant={tenant}/"),
            oauth_server_uri: None,
            oauth_scope: None,
            oauth_audience: None,
        };
        let values = std::collections::HashMap::from([
            ("catalog_credential".into(), "fixture:credential".into()),
            ("access_key_id".into(), "fixture-access".into()),
            ("secret_access_key".into(), "fixture-secret".into()),
        ]);
        let (ct, nonce) = core::seal(&cipher, tenant, values).unwrap();
        sqlx::query("INSERT INTO iceberg_export_settings(tenant_id,enabled,customer_config,credentials_encrypted,credentials_nonce) VALUES($1,true,$2,$3,$4)").bind(tenant).bind(serde_json::to_value(&config).unwrap()).bind(ct).bind(nonce).execute(&pool).await.unwrap();
        let db = Database {
            pool: pool.clone(),
            signer: None,
            tenant,
            actor: Uuid::new_v4(),
        };
        // Explicit local test opt-in; the normal unit suite never mutates this flag.
        assert!(core::feature_enabled());
        let first = claim(&db, &cipher).await.unwrap().unwrap();
        assert!(claim(&db, &cipher).await.unwrap().is_none());
        let mut plan = ExportManifest {
            tenant_id: tenant.to_string(),
            planned_at_ms: 1000,
            previous_plan_ms: None,
            add: vec![],
            remove_parts: vec![],
            hours: vec![],
        };
        let state = ExportState {
            exported: Default::default(),
            last_plan_ms: 1000,
        };
        save_plan(&db, &first, &state, &plan).await.unwrap();
        finish(&db, &first, false, 0, 0, 2, "catalog")
            .await
            .unwrap();
        let settings = {
            let mut tx = db.begin().await.unwrap();
            core::read(&mut tx, tenant, true).await.unwrap()
        };
        assert_eq!(settings.errors["catalog"], 1);
        assert_eq!(settings.lag_hours, 2);
        // A replacement process gets the SAME pending plan, with a fresh fence.
        sqlx::query("UPDATE iceberg_export_settings SET next_run_at=now() WHERE tenant_id=$1")
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        let second = claim(&db, &cipher).await.unwrap().unwrap();
        assert_eq!(second.pending, Some(plan.clone()));
        assert_eq!(second.state.last_plan_ms, 1000);
        assert!(finish(&db, &first, true, 99, 1, 0, "none").await.is_err());
        finish(&db, &second, true, 100, 1, 0, "none").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let settings = core::read(&mut tx, tenant, true).await.unwrap();
        assert!(settings.last_success.is_some());
        assert_eq!(settings.bytes_copied, 100);
        assert_eq!(settings.files, 1);
        assert_eq!(settings.lag_hours, 0);
        tx.commit().await.unwrap();
        // A caller bound to a different tenant cannot acknowledge this claim.
        let otherdb = Database {
            pool,
            signer: None,
            tenant: other,
            actor: db.actor,
        };
        assert!(finish(&otherdb, &second, true, 1, 1, 0, "none")
            .await
            .is_err());
        plan.planned_at_ms = 2000;
        assert!(save_plan(&db, &first, &state, &plan).await.is_err());
        let mut tx = db.begin().await.unwrap();
        let input = core::UpdateExportSettings {
            enabled: false,
            customer: config,
            credentials: None,
            expected_revision: 1,
        };
        assert!(
            !core::update(&mut tx, tenant, &cipher, input)
                .await
                .unwrap()
                .enabled
        );
        tx.commit().await.unwrap();
        assert!(claim(&db, &cipher).await.unwrap().is_none());
    }
}
