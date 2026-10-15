// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fetch the lake field inventory from the query worker.
//!
//! An external `nanosiem-search` — a host process during development, a separate
//! pod in a split deployment — cannot read the generation volume, so its schema
//! historically had to be COPIED out. Nothing published a fresh copy when
//! generations rotated, so a copy taken at setup froze; every field promoted
//! afterwards read as "Unknown canonical OCSF field" regardless of what the lake
//! held. The failure is silent and blames the query rather than the schema.
//!
//! The worker is the authority for what its active generation exposes, so ask it
//! directly. The payload is the merged leaf→type map only — the sole part a
//! schema profile needs, and orders of magnitude smaller than the manifest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use super::{install_lake_schema_field_types, FieldType};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(serde::Deserialize)]
struct SchemaManifestResponse {
    schema_digest: String,
    field_types: BTreeMap<String, FieldType>,
}

/// Where to fetch the schema from, or `None` when the worker endpoints are not
/// configured (an in-container worker reads the volume directly).
pub struct WorkerSchemaSource {
    url: Url,
    bearer_token: String,
    http: reqwest::Client,
    /// NAN-3492: a trusted-local install's dedicated lean cell. When set,
    /// the inventory comes from that tenant's `query[T]` through the cell
    /// router (`url`/`bearer_token` are unused).
    cell: Option<std::sync::Arc<crate::search::LakeCellRoute>>,
}

/// Schema-only reader bearer (NAN-2361). Preferred when set: it authorizes
/// `GET /v1/schema/manifest` and nothing else, so a pod that only needs the
/// field inventory never holds a token that can run `/v1/query`.
pub const LAKE_SCHEMA_TOKEN_FILE_ENV: &str = "NANO_LAKE_SCHEMA_TOKEN_FILE";
/// Full query-reader bearer. Fallback for deployments that have not rendered
/// the schema-only token yet.
pub const LAKE_QUERY_TOKEN_FILE_ENV: &str = "NANO_LAKE_QUERY_TOKEN_FILE";
pub const LAKE_QUERY_URL_ENV: &str = "NANO_LAKE_QUERY_URL";

/// Which bearer file the schema fetch uses: the schema-only token when
/// configured, otherwise the full query token. `None` when neither is set.
///
/// A set-but-blank schema variable counts as unset, so a renderer that emits an
/// empty value does not strand the pod; a set, non-blank one is used as-is and
/// an unreadable file is an error rather than a silent downgrade to the
/// broader credential.
fn select_token_file(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Option<(&'static str, String)> {
    let non_blank = |name: &'static str| {
        lookup(name)
            .filter(|value| !value.trim().is_empty())
            .map(|value| (name, value))
    };
    non_blank(LAKE_SCHEMA_TOKEN_FILE_ENV).or_else(|| non_blank(LAKE_QUERY_TOKEN_FILE_ENV))
}

/// NAN-2718: an hosted shared process serves many tenants. A
/// process-global `NANO_LAKE_QUERY_URL` names ONE tenant's query worker, and
/// installing its schema would show that tenant's field inventory to every
/// tenant (and reject theirs). Refuse to start instead; shared processes load
/// each tenant's schema from its own worker via the shared worker registry.
pub fn refuse_global_schema_in_shared_mode(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), String> {
    let shared = lookup("DEPLOYMENT_MODE").is_some_and(|mode| mode.trim() == "enterprise_shared");
    let global_url = lookup(LAKE_QUERY_URL_ENV).is_some_and(|url| !url.trim().is_empty());
    if shared && global_url {
        return Err(format!(
            "{LAKE_QUERY_URL_ENV} is set in enterprise_shared mode; a single global lake schema \
             would be served to every tenant. Remove it: shared processes resolve each tenant's \
             schema from NANO_LAKE_SHARED_WORKER_REGISTRY_FILE"
        ));
    }
    Ok(())
}

impl WorkerSchemaSource {
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        refuse_global_schema_in_shared_mode(&lookup)?;
        if let Some(route) = crate::search::lake_cell::dedicated_route_from_lookup(&lookup)? {
            tracing::info!(tenant_id = %route.tenant_id, "lake schema fetch configured against the dedicated lean cell");
            return Ok(Some(Self {
                url: Url::parse(&route.query_base_url)
                    .map_err(|error| format!("invalid lake cell route: {error}"))?,
                bearer_token: String::new(),
                http: reqwest::Client::new(),
                cell: Some(route),
            }));
        }
        let (Some(base_url), Some((token_env, token_file))) =
            (lookup(LAKE_QUERY_URL_ENV), select_token_file(&lookup))
        else {
            return Ok(None);
        };
        let parsed = Url::parse(&base_url)
            .map_err(|error| format!("invalid {LAKE_QUERY_URL_ENV}: {error}"))?;
        // Same origin contract the prevalence client enforces: an origin only,
        // so a redirect target or embedded credential cannot be smuggled in.
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(format!("{LAKE_QUERY_URL_ENV} must be an HTTP(S) origin without credentials, query, fragment, or path"));
        }
        // Errors name the variable and the file path, never the token value.
        let bearer_token = std::fs::read_to_string(PathBuf::from(&token_file))
            .map_err(|error| format!("failed to read {token_env} {token_file}: {error}"))?
            .trim()
            .to_string();
        if bearer_token.is_empty() {
            return Err(format!("{token_env} is empty"));
        }
        tracing::info!(
            token_source = token_env,
            "lake schema fetch configured against the query reader"
        );
        let url = parsed
            .join("/v1/schema/manifest")
            .map_err(|error| format!("failed to build schema URL: {error}"))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|error| format!("failed to build schema HTTP client: {error}"))?;
        Ok(Some(Self {
            url,
            bearer_token,
            http,
            cell: None,
        }))
    }

    /// Resolve and install the worker-served schema before a process constructs
    /// its canonical lake profile. A caller with no remote source keeps the
    /// volume-backed deployment contract; a configured but unusable source is
    /// an error, never permission to start with an empty field inventory.
    pub async fn install_from_env() -> Result<Option<Self>, String> {
        let Some(source) = Self::from_env()? else {
            return Ok(None);
        };
        source.refresh().await?;
        Ok(Some(source))
    }

    /// Keep the installed profile current with the authoritative query worker.
    /// Transient faults retain the last verified profile and retry; they never
    /// replace it with an empty or partially decoded schema.
    pub async fn run_refresh_loop(self) {
        self.run_refresh_loop_with(|| {}).await
    }

    /// [`Self::run_refresh_loop`], calling `on_change` after each refresh that
    /// installed a different field set. NAN-3492: a process that pins the
    /// profile in its own state (the API's and jobs' `SharedSchemaProfile`)
    /// republishes [`super::installed_lake_profile`] there; installing it
    /// alone changes nothing those services read.
    pub async fn run_refresh_loop_with(self, on_change: impl Fn() + Send + 'static) {
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match self.refresh().await {
                Ok(true) => {
                    tracing::info!("lake schema changed; profile rebuilt");
                    on_change();
                }
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    %error,
                    "lake schema refresh failed; keeping the installed schema"
                ),
            }
        }
    }

    /// Fetch and install. `Ok(true)` means the field set actually changed.
    ///
    /// A failure leaves any previously installed schema in place: a transient
    /// worker blip must not widen into "every field is unknown", which is how a
    /// schema fault presents to a user.
    pub async fn refresh(&self) -> Result<bool, String> {
        let body = self.fetch().await?;
        install_lake_schema_field_types(&body.schema_digest, body.field_types)
    }

    /// Fetch without installing. Split out so the transport (URL, bearer,
    /// status handling) is testable without touching the process-global
    /// installed profile.
    async fn fetch(&self) -> Result<SchemaManifestResponse, String> {
        if let Some(route) = &self.cell {
            let (schema_digest, field_types) = route
                .fetch_schema_manifest(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .await?;
            return Ok(SchemaManifestResponse {
                schema_digest,
                field_types: super::tenant_lake_schema::cell_inventory_field_types(field_types)?,
            });
        }
        let response = self
            .http
            .get(self.url.clone())
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .map_err(|error| format!("lake schema fetch failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "lake schema fetch returned HTTP {}",
                response.status()
            ));
        }
        response
            .json()
            .await
            .map_err(|error| format!("invalid lake schema response: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SCHEMA_TOKEN: &str = "schema-only-token-0123456789abcdef0123456789";
    const QUERY_TOKEN: &str = "full-query-token-0123456789abcdef0123456789ab";

    fn token_file(dir: &tempfile::TempDir, name: &str, value: &str) -> String {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{value}").unwrap();
        path.to_string_lossy().into_owned()
    }

    fn lookup(vars: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
        move |name| vars.get(name).cloned()
    }

    /// Captures everything logged while it is the default subscriber.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
            let writer = self.clone();
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(move || writer.clone())
                .finish()
        }
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    #[test]
    fn shared_mode_startup_refuses_a_global_schema_url() {
        let dir = tempfile::tempdir().unwrap();
        let error = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            ("DEPLOYMENT_MODE", "enterprise_shared".to_string()),
            (LAKE_QUERY_URL_ENV, "http://nano-query-tenant1.svc:3015".to_string()),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .err()
        .expect("shared mode must refuse a process-global schema URL");
        assert!(error.contains("enterprise_shared"), "{error}");
        // Even without a token (so no fetch would be configured) the URL alone
        // is refused: it is the global schema source by construction.
        assert!(refuse_global_schema_in_shared_mode(&lookup(HashMap::from([
            ("DEPLOYMENT_MODE", "enterprise_shared".to_string()),
            (LAKE_QUERY_URL_ENV, "http://nano-query-tenant1.svc:3015".to_string()),
        ])))
        .is_err());
    }

    #[test]
    fn shared_mode_without_a_global_url_and_dedicated_mode_with_one_are_allowed() {
        assert!(WorkerSchemaSource::from_lookup(lookup(HashMap::from([(
            "DEPLOYMENT_MODE",
            "enterprise_shared".to_string()
        )])))
        .unwrap()
        .is_none());
        let dir = tempfile::tempdir().unwrap();
        assert!(WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            ("DEPLOYMENT_MODE", "enterprise".to_string()),
            (LAKE_QUERY_URL_ENV, "http://reader.invalid:3015".to_string()),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .unwrap()
        .is_some());
    }

    #[test]
    fn schema_token_file_is_preferred_over_the_query_token_file() {
        let selected = select_token_file(&lookup(HashMap::from([
            (LAKE_SCHEMA_TOKEN_FILE_ENV, "/run/schema".to_string()),
            (LAKE_QUERY_TOKEN_FILE_ENV, "/run/query".to_string()),
        ])));
        assert_eq!(selected, Some((LAKE_SCHEMA_TOKEN_FILE_ENV, "/run/schema".to_string())));
    }

    #[test]
    fn query_token_file_is_the_fallback_when_no_schema_token_is_rendered() {
        for schema in [None, Some(""), Some("   ")] {
            let mut vars = HashMap::from([(LAKE_QUERY_TOKEN_FILE_ENV, "/run/query".to_string())]);
            if let Some(value) = schema {
                vars.insert(LAKE_SCHEMA_TOKEN_FILE_ENV, value.to_string());
            }
            assert_eq!(
                select_token_file(&lookup(vars)),
                Some((LAKE_QUERY_TOKEN_FILE_ENV, "/run/query".to_string())),
                "schema value {schema:?}"
            );
        }
        assert_eq!(select_token_file(&lookup(HashMap::new())), None);
    }

    #[test]
    fn schema_token_alone_is_enough_to_configure_the_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let source = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, "http://reader.invalid:3015".to_string()),
            (LAKE_SCHEMA_TOKEN_FILE_ENV, token_file(&dir, "schema", SCHEMA_TOKEN)),
        ])))
        .unwrap()
        .expect("configured");
        assert_eq!(source.bearer_token, SCHEMA_TOKEN);
        assert_eq!(source.url.path(), "/v1/schema/manifest");
    }

    #[test]
    fn an_unreadable_schema_token_file_does_not_fall_back_to_the_query_token() {
        let dir = tempfile::tempdir().unwrap();
        let error = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, "http://reader.invalid:3015".to_string()),
            (LAKE_SCHEMA_TOKEN_FILE_ENV, "/nonexistent/schema-token".to_string()),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .err()
        .expect("unreadable schema token is an error");
        assert!(error.contains(LAKE_SCHEMA_TOKEN_FILE_ENV), "{error}");
        assert!(!error.contains(QUERY_TOKEN), "{error}");
    }

    #[tokio::test]
    async fn fetch_presents_the_schema_token_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/schema/manifest"))
            .and(header("authorization", format!("Bearer {SCHEMA_TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": 1,
                "generation_id": "g",
                "schema_digest": "d1",
                "field_types": { "src_endpoint.ip": "string" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let source = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, server.uri()),
            (LAKE_SCHEMA_TOKEN_FILE_ENV, token_file(&dir, "schema", SCHEMA_TOKEN)),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .unwrap()
        .expect("configured");
        let body = source.fetch().await.expect("schema fetched with the schema token");
        assert_eq!(body.schema_digest, "d1");
        assert_eq!(body.field_types.len(), 1);
    }

    #[tokio::test]
    async fn fetch_falls_back_to_the_query_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/schema/manifest"))
            .and(header("authorization", format!("Bearer {QUERY_TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_digest": "d2",
                "field_types": { "src_endpoint.ip": "string" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let source = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, server.uri()),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .unwrap()
        .expect("configured");
        assert_eq!(source.fetch().await.unwrap().schema_digest, "d2");
    }

    /// No token value may reach a log line or an error string: not on
    /// configuration, not on a rejected fetch.
    #[tokio::test]
    async fn token_values_are_never_logged_or_returned_in_errors() {
        let captured = Captured::default();
        let _guard = tracing::subscriber::set_default(captured.subscriber());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let source = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, server.uri()),
            (LAKE_SCHEMA_TOKEN_FILE_ENV, token_file(&dir, "schema", SCHEMA_TOKEN)),
            (LAKE_QUERY_TOKEN_FILE_ENV, token_file(&dir, "query", QUERY_TOKEN)),
        ])))
        .unwrap()
        .expect("configured");
        let error = source.fetch().await.err().expect("401 is an error");
        tracing::warn!(%error, "lake schema refresh failed; keeping the installed schema");
        let empty_error = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            (LAKE_QUERY_URL_ENV, server.uri()),
            (LAKE_SCHEMA_TOKEN_FILE_ENV, token_file(&dir, "blank", "  ")),
        ])))
        .err()
        .expect("blank token file is an error");
        let logs = captured.text();
        // Proves the capture is live. (Whether the `info!` in `from_lookup`
        // lands here depends on process-global callsite-interest caching shared
        // with parallel tests, so it is not asserted positively.)
        assert!(logs.contains("lake schema refresh failed"), "capture is live: {logs}");
        for text in [logs.as_str(), error.as_str(), empty_error.as_str()] {
            assert!(!text.contains(SCHEMA_TOKEN), "schema token leaked: {text}");
            assert!(!text.contains(QUERY_TOKEN), "query token leaked: {text}");
        }
    }

    /// NAN-3492: a trusted-local install fetches its inventory from the
    /// dedicated cell's query[T] through the router, never the gen1 URL.
    #[tokio::test]
    async fn dedicated_cell_route_serves_the_schema() {
        use std::os::unix::fs::PermissionsExt;
        const TENANT: &str = "6f3d1060-5b8e-4d4c-9a3e-0e2b7c9c7106";
        let server = MockServer::start().await;
        let digest = "ab".repeat(32);
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{TENANT}/query/v1/schema/manifest")))
            .and(header("authorization", format!("Bearer {QUERY_TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": TENANT, "source_mode": "parts", "schema_digest": digest,
                "field_types": {"src_endpoint.ip": "string", "time": "timestamp"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let token = token_file(&dir, "router-query.token", QUERY_TOKEN);
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
        let routes = dir.path().join("routes.json");
        std::fs::write(&routes, serde_json::json!({TENANT: {"cell_origin": server.uri(),
            "assignment_generation": 1, "part_log_writer_epoch": 1, "worker_revision": 1}}).to_string()).unwrap();
        let source = WorkerSchemaSource::from_lookup(lookup(HashMap::from([
            ("NANO_LAKE_CELL_ROUTES_FILE", routes.display().to_string()),
            ("NANO_LAKE_CELL_ROUTER_TOKEN_FILE", token),
            ("NANO_LAKE_TENANT_ID", TENANT.to_string()),
        ])))
        .unwrap()
        .expect("the dedicated cell is a schema source");
        let body = source.fetch().await.unwrap();
        assert_eq!(body.schema_digest, digest);
        assert!(body.field_types.contains_key("src_endpoint.ip"));
    }
}
