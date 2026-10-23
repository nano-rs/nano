//! Private, bounded Squid authorization. Uses the existing egress credential
//! names; no enable flag and no direct fallback. Origins only leave the service.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use nanosiem_core::egress::{Grant, Grants, LOCAL_TENANT, Origin, Principal, Purpose, Source};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone)]
pub struct EgressState {
    key: Arc<Vec<u8>>,
    source: Arc<dyn Source>,
    admission: Arc<Semaphore>,
}
impl EgressState {
    pub fn new(key: Vec<u8>, source: Arc<dyn Source>) -> Result<Self, &'static str> {
        if key.len() < 32 {
            return Err("invalid proxy authority");
        }
        Ok(Self {
            key: Arc::new(key),
            source,
            admission: Arc::new(Semaphore::new(64)),
        })
    }
    fn principal(&self, headers: &HeaderMap) -> Result<(Uuid, Purpose), StatusCode> {
        let raw = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        Principal::verify(&self.key, raw).ok_or(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = PurposeEgressCheckRequest)]
pub struct CheckRequest {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub connect: bool,
}
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct CheckResponse {
    pub allow: bool,
    pub tenant: Uuid,
    pub purpose: Purpose,
}

#[utoipa::path(post, path="/internal/egress/check", tag="internal-egress", request_body=CheckRequest,
    responses((status=200,body=CheckResponse),(status=400),(status=401),(status=403),(status=429),(status=503)), security(("proxy_principal"=[])))]
pub async fn check(
    State(state): State<EgressState>,
    headers: HeaderMap,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, StatusCode> {
    let (tenant, purpose) = state.principal(&headers)?;
    // Inventory access must not weaken the existing connection/revision-bound
    // SOAR tunnel authorization. Those requests use its existing endpoint.
    if purpose == Purpose::Soar {
        return Err(StatusCode::FORBIDDEN);
    }
    let _permit = state
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let raw = format!("{}://{}:{}", request.scheme, request.host, request.port);
    let origin = Origin::from_url(&raw, purpose).map_err(|_| StatusCode::BAD_REQUEST)?;
    if origin.as_str() != raw || request.connect != (request.scheme == "https") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let grants = tokio::time::timeout(
        Duration::from_millis(900),
        state.source.grants(tenant, purpose),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let acl = Grants::compile(&grants).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // A source returning another tenant's grants never authorizes the caller.
    let allow = acl.permits(tenant, purpose, &origin);
    metrics::counter!("nano_egress_decisions_total", "purpose" => purpose.as_str(), "decision" => if allow {"allow"} else {"deny"}).increment(1);
    if !allow {
        tracing::warn!(%tenant, purpose=purpose.as_str(), origin=origin.as_str(), "egress destination denied");
    }
    Ok(Json(CheckResponse {
        allow,
        tenant,
        purpose,
    }))
}

/// Raw resolved requirements are origin-only and tenant scoped. Kept separate
/// from the compiled ACL read so collection compares configuration against
/// what the check service can actually authorize.
#[utoipa::path(get,path="/internal/egress/requirements",tag="internal-egress",
    responses((status=200,body=Vec<Grant>),(status=401),(status=429),(status=503)),security(("proxy_principal"=[])))]
pub async fn requirements(
    State(state): State<EgressState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Grant>>, StatusCode> {
    let (tenant, purpose) = state.principal(&headers)?;
    let _permit = state
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let mut grants = tokio::time::timeout(
        Duration::from_millis(900),
        state.source.grants(tenant, purpose),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if grants
        .iter()
        .any(|g| g.tenant_id != tenant || g.purpose != purpose)
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    for grant in &mut grants {
        grant.origin = Origin::from_url(grant.origin.as_str(), purpose)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    Ok(Json(grants))
}

#[utoipa::path(get, path="/internal/egress/acl", tag="internal-egress",
    responses((status=200,body=Vec<Grant>),(status=401),(status=429),(status=503)), security(("proxy_principal"=[])))]
pub async fn acl(
    State(state): State<EgressState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Grant>>, StatusCode> {
    let (tenant, purpose) = state.principal(&headers)?;
    let _permit = state
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let mut grants = tokio::time::timeout(
        Duration::from_millis(900),
        state.source.grants(tenant, purpose),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Grants::compile(&grants).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if grants
        .iter()
        .any(|g| g.tenant_id != tenant || g.purpose != purpose)
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    for grant in &mut grants {
        grant.origin = Origin::from_url(grant.origin.as_str(), purpose)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    let compiled = Grants::compile(&grants).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        grants
            .into_iter()
            .filter(|g| compiled.permits(tenant, purpose, &g.origin))
            .collect(),
    ))
}

#[utoipa::path(get,path="/internal/egress/tenants",tag="internal-egress",
    responses((status=200,body=Vec<Uuid>),(status=401),(status=403),(status=503)),security(("proxy_principal"=[])))]
pub async fn tenants(
    State(state): State<EgressState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Uuid>>, StatusCode> {
    let (tenant, purpose) = state.principal(&headers)?;
    if tenant != LOCAL_TENANT || purpose != Purpose::Platform {
        return Err(StatusCode::FORBIDDEN);
    }
    let ids = tokio::time::timeout(Duration::from_millis(900), state.source.tenant_ids())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(ids))
}

pub fn router(state: EgressState) -> Router {
    Router::new()
        .route("/internal/egress/check", post(check))
        .route("/internal/egress/acl", get(acl))
        .route("/internal/egress/tenants", get(tenants))
        .route("/internal/egress/requirements", get(requirements))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(state)
}

/// Projected by the hosted control plane from a recorded control DB authority admission and
/// the registered region spec. This file shares the owned, read-only origins
/// ConfigMap mount; a key/env variable alone cannot expose the internal API.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAdmission {
    schema: String,
    deployment_id: String,
    cluster_id: String,
    region: String,
    stage: String,
    evidence_sha256: String,
    accepted_at: String,
    app_hostname: String,
}
impl RuntimeAdmission {
    fn read(path: &std::path::Path, deployment_id: Option<&str>) -> Option<Self> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path).ok()?.take(8193).read_to_end(&mut bytes).ok()?;
        if bytes.len() > 8192 { return None; }
        let row: Self = serde_json::from_slice(&bytes).ok()?;
        if row.schema != "nano-egress-admission/v1" || row.stage != "authority"
            || row.deployment_id.is_empty() || deployment_id != Some(row.deployment_id.as_str())
            || row.cluster_id.is_empty() || row.cluster_id.len() > 253
            || row.region.is_empty() || row.region.len() > 63
            || row.evidence_sha256.len() != 64 || !row.evidence_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || chrono::DateTime::parse_from_rfc3339(&row.accepted_at).is_err()
            || !row.app_hostname.ends_with(".nano.rs") || row.app_hostname.len() > 253
            || row.app_hostname.split('.').any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) {
            return None;
        }
        Some(row)
    }
}

pub const RUNTIME_ADMISSION_PATH: &str = "/etc/nano/egress/admission.json";

struct RuntimeSource {
    app: crate::state::AppState,
    admission: RuntimeAdmission,
}
impl RuntimeSource {
    fn shared(&self) -> bool {
        #[cfg(feature = "enterprise")]
        {
            self.app.config.deployment_mode.is_enterprise_shared()
        }
        #[cfg(not(feature = "enterprise"))]
        {
            false
        }
    }
}
#[async_trait::async_trait]
impl Source for RuntimeSource {
    async fn tenant_ids(&self) -> Result<Vec<Uuid>, &'static str> {
        if !self.shared() {
            return Ok(vec![LOCAL_TENANT]);
        }
        let ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM public.tenants WHERE status='active' ORDER BY id LIMIT 10001",
        )
        .fetch_all(&self.app.pool)
        .await
        .map_err(|_| "tenant inventory unavailable")?;
        if ids.len() > 10000 {
            return Err("tenant inventory oversized");
        }
        Ok(ids)
    }
    async fn grants(&self, tenant: Uuid, purpose: Purpose) -> Result<Vec<Grant>, &'static str> {
        use nanosiem_core::egress::{FEED_HOSTS, host_grants};
        let deployment = match std::fs::read("/etc/nano/egress/origins.json") {
            Ok(bytes) if bytes.len() <= 1024 * 1024 => serde_json::from_slice::<Vec<Grant>>(&bytes)
                .map_err(|_| "invalid deployment authority")?,
            Ok(_) => return Err("deployment authority oversized"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err("deployment authority unavailable"),
        };
        Grants::compile(&deployment)?;
        if purpose == Purpose::Supervisor {
            let grants: Vec<_> = deployment.iter().filter(|g| g.tenant_id == tenant && g.purpose == Purpose::Supervisor).cloned().collect();
            if grants.is_empty() { return Err("cell authority unavailable"); }
            return Ok(grants);
        }
        // Platform purposes have a distinct principal, never a tenant-wide
        // union. Deployment origins contain no secrets and are mounted by the
        // production renderer from the region's validated service facts.
        if tenant == LOCAL_TENANT
            && matches!(
                purpose,
                Purpose::Feed
                    | Purpose::Storage
                    | Purpose::Catalog
                    | Purpose::Converter
                    | Purpose::Registry
                    | Purpose::Telemetry
                    | Purpose::Platform
                    | Purpose::Ai
            )
        {
            let hosts: Vec<String> = match purpose {
                Purpose::Feed => FEED_HOSTS.iter().map(|h| (*h).into()).collect(),
                Purpose::Converter => vec![
                    "api.github.com".into(),
                    "codeload.github.com".into(),
                    "api.anthropic.com".into(),
                ],
                Purpose::Registry => vec!["ghcr.io".into(), "registry.cloudflare.com".into()],
                Purpose::Telemetry => vec!["ops.ingest.nano.rs".into()],
                Purpose::Platform => vec![
                    "api.cloudflare.com".into(),
                    "api.doppler.com".into(),
                    "api.stripe.com".into(),
                    "api.github.com".into(),
                    "github.com".into(), "codeload.github.com".into(), "objects.githubusercontent.com".into(),
                    "api.resend.com".into(), "spot.rackspace.com".into(), "login.spot.rackspace.com".into(), "api.planetscale.com".into(),
                ],
                _ => Vec::new(),
            };
            let mut grants = host_grants(tenant, purpose, hosts, "coded-v1", "platform")?;
            grants.extend(
                deployment
                    .iter()
                    .filter(|g| g.tenant_id == tenant && g.purpose == purpose)
                    .cloned(),
            );
            // Self-hosted external object endpoints use the existing runtime
            // configuration. Internal RustFS/Lakekeeper bypass public egress.
            if matches!(purpose, Purpose::Storage | Purpose::Catalog | Purpose::Feed) {
                for name in [
                    "NANO_LAKE_OBJECT_ENDPOINT",
                    "NANO_LAKE_RESULT_S3_ENDPOINT",
                    "PLATFORM_FEED_S3_ENDPOINT",
                ] {
                    if let Ok(raw) = std::env::var(name) {
                        if let Ok(origin) = Origin::from_url(&raw, purpose) {
                            grants.push(Grant {
                                tenant_id: tenant,
                                purpose,
                                origin,
                                revision: "deployment-config".into(),
                                workload: "lake".into(),
                            });
                        }
                    }
                }
            }
            if purpose == Purpose::Ai {
                if let Ok(url) = std::env::var("CLOUDFLARE_AI_GATEWAY_URL") {
                    if !url.is_empty() {
                        grants.push(Grant {
                            tenant_id: tenant,
                            purpose,
                            origin: Origin::from_url(&url, purpose)?,
                            revision: "deployment-ai-gateway".into(),
                            workload: "api/jobs/search".into(),
                        });
                    }
                }
                if !self.shared() {
                    let rows=sqlx::query_as::<_,(String,serde_json::Value,i64)>("SELECT provider,config,credential_revision FROM public.provider_credentials WHERE enabled ORDER BY provider LIMIT 65")
                        .fetch_all(&self.app.pool).await.map_err(|_|"AI authority unavailable")?;
                    if rows.len() > 64 {
                        return Err("AI authority oversized");
                    }
                    for (provider, config, revision) in rows {
                        if let Some(url) = nanosiem_core::ai_provider::direct_base_url(&config) {
                            grants.push(Grant {
                                tenant_id: tenant,
                                purpose,
                                origin: Origin::from_url(&url, purpose)?,
                                revision: format!("{provider}:{revision}"),
                                workload: "api/jobs/search".into(),
                            });
                        }
                    }
                }
            }
            return Ok(grants);
        }
        #[cfg(feature = "enterprise")]
        if self.shared() {
            let runtime = self
                .app
                .tenant_ai_rls_runtime
                .clone()
                .ok_or("tenant authority unavailable")?;
            let source = nanosiem_enterprise::egress::TenantEgressSource::new(
                runtime,
                nanosiem_core::auth::TenantMembershipResolver::new(self.app.pool.clone()),
                self.app.encryption_service.clone(),
                self.app.pool.clone(),
            );
            if purpose == Purpose::Soar {
                return source
                    .soar_grants(
                        self.app.soar_service.as_deref().ok_or("SOAR unavailable")?,
                        tenant,
                    )
                    .await;
            }
            let mut extra: Vec<Grant> = deployment
                .iter()
                .filter(|g| g.tenant_id == tenant && g.purpose == purpose)
                .cloned()
                .collect();
            if matches!(
                purpose,
                Purpose::Storage | Purpose::Catalog | Purpose::Platform
            ) {
                source.require_active(tenant).await?;
                if purpose != Purpose::Platform {
                    extra.extend(
                        deployment
                            .iter()
                            .filter(|g| g.tenant_id == LOCAL_TENANT && g.purpose == purpose)
                            .cloned()
                            .map(|mut grant| {
                                grant.tenant_id = tenant;
                                grant
                            }),
                    );
                }
                if purpose == Purpose::Storage {
                    extra.extend(source.grants(tenant, purpose).await?);
                }
                if purpose == Purpose::Platform {
                    // Coded deployment tools are tenant bound, including births
                    // after the last region-origin snapshot. No global vendor union.
                    extra.extend(host_grants(
                        tenant,
                        purpose,
                        ["api.cloudflare.com".into(), self.admission.app_hostname.clone()],
                        "coded-worker-deployer-v1",
                        "worker-deployer",
                    )?);
                }
                return Ok(extra);
            }
            if purpose == Purpose::Ai {
                extra.extend(
                    deployment
                        .iter()
                        .filter(|g| g.tenant_id == LOCAL_TENANT && g.purpose == purpose)
                        .cloned()
                        .map(|mut g| {
                            g.tenant_id = tenant;
                            g
                        }),
                );
                if let Ok(url) = std::env::var("CLOUDFLARE_AI_GATEWAY_URL") {
                    if !url.is_empty() {
                        extra.push(Grant {
                            tenant_id: tenant,
                            purpose,
                            origin: Origin::from_url(&url, purpose)?,
                            revision: "deployment-ai-gateway".into(),
                            workload: "api/jobs/search".into(),
                        });
                    }
                }
            }
            let mut grants = source.grants(tenant, purpose).await?;
            grants.extend(extra);
            return Ok(grants);
        }
        if tenant != LOCAL_TENANT {
            return Err("invalid deployment principal");
        }
        let mut grants = Vec::new();
        match purpose {
            Purpose::Webhook => {
                let webhooks = nanosiem_core::webhooks::WebhookRepository::with_encryption(
                    self.app.pool.clone(),
                    (*self.app.encryption_service).clone(),
                )
                .list()
                .await
                .map_err(|_| "webhook authority unavailable")?;
                for webhook in webhooks {
                    let url = match webhook.url_encrypted.as_deref() {
                        Some(bytes) => nanosiem_core::webhooks::repository::decrypt_envelope_string(
                            &self.app.encryption_service.with_context(nanosiem_core::crypto::CredentialScope::Deployment,"webhook.url",webhook.id),bytes).ok(),
                        None => Some(webhook.url.clone()),
                    };
                    let origin = url.and_then(|raw| Origin::from_url(&raw,purpose).ok());
                    let Some(origin) = origin else {nanosiem_core::egress::invalid_webhook_row();continue;};
                    grants.push(Grant {tenant_id:tenant,purpose,origin,revision:format!("{}:{}",webhook.id,webhook.updated_at.timestamp_micros()),workload:"api/jobs".into()});
                }
            }
            Purpose::Connector => {
                let rows = sqlx::query_as::<_, (String,String,serde_json::Value)>("SELECT spec_yaml,spec_sha256,config FROM public.connector_feeds WHERE enabled ORDER BY tenant_id,id LIMIT 513")
                    .fetch_all(&self.app.pool).await.map_err(|_| "connector authority unavailable")?;
                if rows.len() > 512 {
                    return Err("connector authority oversized");
                }
                for (yaml, sha, config) in rows {
                    grants.extend(nano_connector::egress_policy::connector_grants(
                        tenant, &yaml, &sha, config,
                    )?);
                }
            }
            #[cfg(feature = "enterprise")]
            Purpose::CustomEnrichment => {
                let rows=sqlx::query_as::<_,(Uuid,i32,Vec<String>,serde_json::Value)>(
                    "SELECT id,code_version,allowed_domains,config FROM public.custom_enrichments ORDER BY id LIMIT 513")
                    .fetch_all(&self.app.pool).await.map_err(|_| "enrichment authority unavailable")?;
                if rows.len() > 512 {
                    return Err("enrichment authority oversized");
                }
                for (id, revision, hosts, config) in rows {
                    let revision = format!("{id}:{revision}");
                    grants.extend(nanosiem_core::egress::host_grants(
                        tenant, purpose, hosts, &revision, "api/jobs",
                    )?);
                    if let Some(url) = config
                        .pointer("/auth_config/token_url")
                        .and_then(serde_json::Value::as_str)
                    {
                        grants.push(Grant {
                            tenant_id: tenant,
                            purpose,
                            origin: Origin::from_url(url, purpose)?,
                            revision,
                            workload: "api/jobs".into(),
                        });
                    }
                }
            }
            _ => return Err("purpose unavailable in this deployment"),
        }
        Ok(grants)
    }
}

pub fn runtime_router(app: &crate::state::AppState, admission_file: &std::path::Path) -> Router {
    let Some(admission) = RuntimeAdmission::read(admission_file, app.config.deployment_id.as_deref()) else {
        return Router::new();
    };
    let source = RuntimeSource { app: app.clone(), admission };
    if source.shared() && std::env::var_os("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY").is_none() {
        return Router::new();
    }
    let Ok(key) = nanosiem_core::egress::key_from_env() else {
        return Router::new();
    };
    let state = EgressState::new(key, Arc::new(source)).expect("validated key");
    router(state)
}

struct Security;
impl utoipa::Modify for Security {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
        if let Some(c) = openapi.components.as_mut() {
            c.add_security_scheme(
                "proxy_principal",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Basic)),
            );
        }
    }
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(check,acl,tenants,requirements),components(schemas(CheckRequest,CheckResponse,Grant,Purpose,Origin)),modifiers(&Security))]
pub struct EgressApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[test]
    fn egress_admission_is_bounded_stage_and_deployment_bound() {
        let dir=tempfile::tempdir().unwrap();let path=dir.path().join("admission.json");
        assert!(RuntimeAdmission::read(&path,Some("deployment-a")).is_none());
        let row=serde_json::json!({"schema":"nano-egress-admission/v1","deployment_id":"deployment-a","cluster_id":"uk-cluster","region":"uk-lon-1","stage":"authority",
            "evidence_sha256":"a".repeat(64),"accepted_at":"2026-10-23T00:00:00Z","app_hostname":"uk.nano.rs"});
        std::fs::write(&path,serde_json::to_vec(&row).unwrap()).unwrap();
        assert_eq!(RuntimeAdmission::read(&path,Some("deployment-a")).unwrap().app_hostname,"uk.nano.rs");
        assert!(RuntimeAdmission::read(&path,Some("deployment-b")).is_none());
        assert!(RuntimeAdmission::read(&path,None).is_none());
        for (field,bad) in [("stage","tenant-pulls"),("schema","unknown"),("evidence_sha256","invalid"),("accepted_at","invalid"),("app_hostname","*.nano.rs"),("app_hostname","https://uk.nano.rs/path"),("app_hostname","foreign.example")] {
            let mut invalid=row.clone();invalid[field]=serde_json::json!(bad);
            std::fs::write(&path,serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(RuntimeAdmission::read(&path,Some("deployment-a")).is_none(),"{field}");
        }
        std::fs::write(&path,vec![b' ';8193]).unwrap();
        assert!(RuntimeAdmission::read(&path,Some("deployment-a")).is_none());
    }
    struct Current;
    #[async_trait::async_trait]
    impl Source for Current {
        async fn grants(&self, tenant: Uuid, purpose: Purpose) -> Result<Vec<Grant>, &'static str> {
            Ok(vec![Grant {
                tenant_id: Uuid::from_u128(10),
                purpose: Purpose::Webhook,
                origin: Origin::from_url("http://receiver.example", Purpose::Webhook).unwrap(),
                revision: "configured-webhook".into(),
                workload: "api/jobs".into(),
            }]
            .into_iter()
            .filter(|g| g.tenant_id == tenant && g.purpose == purpose)
            .collect())
        }
    }
    #[tokio::test]
    async fn guarded_production_router_checks_credentials_tenant_purpose_origin_and_transport() {
        let key = vec![7; 32];
        assert!(EgressState::new(vec![7; 31], Arc::new(Current)).is_err());
        let state = EgressState::new(key.clone(), Arc::new(Current)).unwrap();
        for (tenant, purpose, host, scheme, port, connect, status, allow) in [
            (
                10,
                Purpose::Webhook,
                "receiver.example",
                "http",
                80,
                false,
                200,
                true,
            ),
            (
                11,
                Purpose::Webhook,
                "receiver.example",
                "http",
                80,
                false,
                200,
                false,
            ),
            (
                10,
                Purpose::Webhook,
                "unlisted.example",
                "http",
                80,
                false,
                200,
                false,
            ),
            (
                10,
                Purpose::Connector,
                "receiver.example",
                "http",
                80,
                false,
                400,
                false,
            ),
            (
                10,
                Purpose::Webhook,
                "receiver.example",
                "http",
                80,
                true,
                400,
                false,
            ),
            (
                10,
                Purpose::Webhook,
                "receiver.example",
                "https",
                443,
                true,
                200,
                false,
            ),
        ] {
            let auth = Principal::new(&key, Uuid::from_u128(tenant), purpose)
                .unwrap()
                .basic();
            let request = Request::builder()
                .method("POST")
                .uri("/internal/egress/check")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"scheme":scheme,"host":host,"port":port,"connect":connect})
                        .to_string(),
                ))
                .unwrap();
            let response = router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            if status == 200 {
                let bytes = axum::body::to_bytes(response.into_body(), 2048)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<CheckResponse>(&bytes)
                        .unwrap()
                        .allow,
                    allow
                );
            }
        }
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/egress/acl")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    struct Foreign;
    #[async_trait::async_trait]
    impl Source for Foreign {
        async fn grants(
            &self,
            _tenant: Uuid,
            _purpose: Purpose,
        ) -> Result<Vec<Grant>, &'static str> {
            Ok(vec![Grant {
                tenant_id: Uuid::from_u128(99),
                purpose: Purpose::Webhook,
                origin: Origin::from_url("https://receiver.example", Purpose::Webhook).unwrap(),
                revision: "row".into(),
                workload: "api/jobs".into(),
            }])
        }
    }
    #[tokio::test]
    async fn foreign_source_rows_never_grant_or_leak_and_inventory_cannot_authorize_soar() {
        let key = vec![7; 32];
        let tenant = Uuid::from_u128(10);
        let state = EgressState::new(key.clone(), Arc::new(Foreign)).unwrap();
        for path in ["/internal/egress/acl", "/internal/egress/requirements"] {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(
                            "authorization",
                            Principal::new(&key, tenant, Purpose::Webhook)
                                .unwrap()
                                .basic(),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        for (purpose, expected) in [(Purpose::Soar, 403), (Purpose::Webhook, 200)] {
            let response=router(state.clone()).oneshot(Request::builder().method("POST").uri("/internal/egress/check")
                .header("authorization",Principal::new(&key,tenant,purpose).unwrap().basic()).header("content-type","application/json")
                .body(Body::from(r#"{"scheme":"https","host":"receiver.example","port":443,"connect":true}"#)).unwrap()).await.unwrap();
            assert_eq!(response.status().as_u16(), expected);
            if expected == 200 {
                let bytes = axum::body::to_bytes(response.into_body(), 2048)
                    .await
                    .unwrap();
                assert!(
                    !serde_json::from_slice::<CheckResponse>(&bytes)
                        .unwrap()
                        .allow
                );
            }
        }
        for auth in [None, Some("Basic malformed"), Some("Bearer secret")] {
            let mut request = Request::builder().uri("/internal/egress/tenants");
            if let Some(auth) = auth {
                request = request.header("authorization", auth);
            }
            assert_eq!(
                router(state.clone())
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/egress/tenants")
                    .header(
                        "authorization",
                        Principal::new(&key, tenant, Purpose::Platform)
                            .unwrap()
                            .basic(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
