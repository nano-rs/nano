// SPDX-License-Identifier: AGPL-3.0-or-later

//! Narrow Iceberg REST commit seam for actions not yet exposed by iceberg-rust.
//!
//! The normal catalog client remains authoritative for table loading and all
//! supported transactions. Retention needs a standards-compliant `delete`
//! snapshot today, while iceberg-rust 0.10.1 only exposes append and snapshot
//! expiry. This module deliberately implements only the REST commit envelope;
//! callers still construct standard Iceberg manifests, snapshots, requirements,
//! and updates with iceberg-rust's public types.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use iceberg::{TableIdent, TableRequirement, TableUpdate};
use iceberg_catalog_rest::{CommitTableRequest, CommitTableResponse};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;

use crate::iceberg::CatalogConfig;

#[derive(Debug)]
pub enum CommitOutcome {
    Committed(CommitTableResponse),
    Conflict,
}

#[derive(Debug, Deserialize)]
struct RuntimeCatalogConfig {
    #[serde(default)]
    defaults: HashMap<String, String>,
    #[serde(default)]
    overrides: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

pub struct RestTableCommitClient {
    client: Client,
    endpoint: String,
    token: Option<String>,
    realm: Option<String>,
    vended_credentials: bool,
    table_id: TableIdent,
}

impl RestTableCommitClient {
    pub async fn new(config: &CatalogConfig, table_id: &TableIdent) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        let token = catalog_token(&client, config).await?;
        let base = config.uri.trim_end_matches('/');
        let request = authenticated(
            client
                .get(format!("{base}/v1/config"))
                .query(&[("warehouse", config.warehouse.as_str())]),
            token.as_deref(),
            config.realm.as_deref(),
            config.vended_credentials,
        );
        let response = request
            .send()
            .await
            .context("fetch Iceberg REST runtime config")?;
        if response.status() != StatusCode::OK {
            return Err(response_error(response, "fetch Iceberg REST runtime config").await);
        }
        let runtime: RuntimeCatalogConfig = response
            .json()
            .await
            .context("decode Iceberg REST runtime config")?;
        let runtime_uri = runtime
            .overrides
            .get("uri")
            .map(String::as_str)
            .unwrap_or(base)
            .trim_end_matches('/');
        if runtime_uri.is_empty()
            || runtime_uri.len() > 2_048
            || runtime_uri.chars().any(char::is_control)
        {
            bail!("Iceberg REST runtime URI is invalid");
        }
        let prefix = runtime
            .overrides
            .get("prefix")
            .or_else(|| runtime.defaults.get("prefix"))
            .map(String::as_str)
            .filter(|value| !value.is_empty());
        let namespace = table_id.namespace.to_url_string();
        let mut endpoint = format!("{runtime_uri}/v1/");
        if let Some(prefix) = prefix {
            if prefix.len() > 1_024
                || prefix.chars().any(char::is_control)
                || prefix.starts_with('/')
                || prefix.ends_with('/')
            {
                bail!("Iceberg REST runtime prefix is invalid");
            }
            endpoint.push_str(prefix);
            endpoint.push('/');
        }
        endpoint.push_str("namespaces/");
        endpoint.push_str(&namespace);
        endpoint.push_str("/tables/");
        endpoint.push_str(&table_id.name);
        Ok(Self {
            client,
            endpoint,
            token,
            realm: config.realm.clone(),
            vended_credentials: config.vended_credentials,
            table_id: table_id.clone(),
        })
    }

    pub async fn commit(
        &self,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<CommitOutcome> {
        if requirements.is_empty() || updates.is_empty() {
            bail!("direct Iceberg REST commits require explicit requirements and updates");
        }
        let response = authenticated(
            self.client.post(&self.endpoint).json(&CommitTableRequest {
                identifier: Some(self.table_id.clone()),
                requirements,
                updates,
            }),
            self.token.as_deref(),
            self.realm.as_deref(),
            self.vended_credentials,
        )
        .send()
        .await
        .context("commit Iceberg REST table update")?;
        match response.status() {
            StatusCode::OK => Ok(CommitOutcome::Committed(
                response
                    .json()
                    .await
                    .context("decode Iceberg REST commit response")?,
            )),
            StatusCode::CONFLICT => Ok(CommitOutcome::Conflict),
            _ => Err(response_error(response, "commit Iceberg REST table update").await),
        }
    }
}

fn authenticated(
    mut request: RequestBuilder,
    token: Option<&str>,
    realm: Option<&str>,
    vended_credentials: bool,
) -> RequestBuilder {
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(realm) = realm {
        request = request.header("Polaris-Realm", realm);
    }
    if vended_credentials {
        request = request.header("X-Iceberg-Access-Delegation", "vended-credentials");
    }
    request.header("X-Client-Version", "1.0.0").header(
        reqwest::header::USER_AGENT,
        format!("nano-lake/{}", env!("CARGO_PKG_VERSION")),
    )
}

async fn catalog_token(client: &Client, config: &CatalogConfig) -> Result<Option<String>> {
    if let Some(path) = &config.token_file {
        let value = std::fs::read_to_string(path)
            .with_context(|| format!("read catalog workload token {}", path.display()))?;
        let token = value.trim_end_matches(['\n', '\r']);
        validate_token(token)?;
        return Ok(Some(token.to_string()));
    }
    let Some(credential) = config.credential.as_deref() else {
        if config.allow_anonymous {
            return Ok(None);
        }
        bail!("Iceberg REST commit authentication is required");
    };
    let (client_id, client_secret) = credential
        .split_once(':')
        .map_or((None, credential), |(id, secret)| (Some(id), secret));
    if client_secret.is_empty() || client_secret.chars().any(char::is_control) {
        bail!("Iceberg REST OAuth credential is invalid");
    }
    let endpoint = config
        .oauth_server_uri
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}/v1/oauth/tokens", config.uri.trim_end_matches('/')));
    let mut form = vec![
        ("grant_type", "client_credentials"),
        ("client_secret", client_secret),
        ("scope", config.oauth_scope.as_deref().unwrap_or("catalog")),
    ];
    if let Some(client_id) = client_id {
        form.push(("client_id", client_id));
    }
    if let Some(audience) = config.oauth_audience.as_deref() {
        form.push(("audience", audience));
    }
    let response = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .context("exchange Iceberg REST OAuth credential")?;
    if response.status() != StatusCode::OK {
        return Err(response_error(response, "exchange Iceberg REST OAuth credential").await);
    }
    let token: TokenResponse = response
        .json()
        .await
        .context("decode Iceberg REST OAuth token")?;
    validate_token(&token.access_token)?;
    Ok(Some(token.access_token))
}

fn validate_token(token: &str) -> Result<()> {
    if !(32..=16_384).contains(&token.len()) || token.chars().any(char::is_control) {
        bail!("Iceberg REST workload token is invalid");
    }
    Ok(())
}

async fn response_error(response: reqwest::Response, operation: &str) -> anyhow::Error {
    let status = response.status();
    // Catalog/OAuth error bodies can echo credentials and need not be bounded.
    // Preserve only operation/status; never buffer or log a remote error body.
    anyhow::anyhow!("{operation} failed with HTTP {status}")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use serde_json::{json, Value};

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Value>>>);

    async fn oauth() -> axum::Json<Value> {
        axum::Json(json!({"access_token": "t".repeat(64)}))
    }

    async fn runtime_config() -> axum::Json<Value> {
        axum::Json(json!({"defaults": {}, "overrides": {"prefix": "warehouse-a"}}))
    }

    async fn conflict(
        State(capture): State<Capture>,
        headers: HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> StatusCode {
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some(format!("Bearer {}", "t".repeat(64)).as_str())
        );
        capture.0.lock().unwrap().push(body);
        StatusCode::CONFLICT
    }

    #[tokio::test]
    async fn discovers_prefix_authenticates_and_surfaces_conflict() {
        let capture = Capture::default();
        let app = Router::new()
            .route("/oauth", post(oauth))
            .route("/catalog/v1/config", get(runtime_config))
            .route(
                "/catalog/v1/warehouse-a/namespaces/default/tables/events",
                post(conflict),
            )
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = CatalogConfig {
            uri: format!("http://{address}/catalog"),
            warehouse: "nano".to_string(),
            credential: Some(format!("client:{}", "s".repeat(64))),
            token_file: None,
            oauth_scope: Some("lakekeeper".to_string()),
            oauth_audience: Some("lakekeeper".to_string()),
            oauth_server_uri: Some(format!("http://{address}/oauth")),
            realm: None,
            allow_anonymous: false,
            s3_endpoint: String::new(),
            s3_region: "us-east-1".to_string(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            s3_session_token: None,
            s3_path_style_access: true,
            s3_default_credentials: true,
            vended_credentials: false,
        };
        let table = TableIdent::from_strs(["default", "events"]).unwrap();
        let client = RestTableCommitClient::new(&config, &table).await.unwrap();
        let outcome = client
            .commit(
                vec![TableRequirement::UuidMatch {
                    uuid: uuid::Uuid::nil(),
                }],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("test".to_string(), "true".to_string())]),
                }],
            )
            .await
            .unwrap();
        assert!(matches!(outcome, CommitOutcome::Conflict));
        let bodies = capture.0.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["identifier"]["name"], "events");
        assert_eq!(bodies[0]["requirements"][0]["type"], "assert-table-uuid");
    }

    #[tokio::test]
    async fn remote_error_body_cannot_expose_credentials() {
        let marker = "fixture-only-sensitive-marker";
        let app = Router::new().route(
            "/",
            get(|| async { (StatusCode::UNAUTHORIZED, "fixture-only-sensitive-marker") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let error = response_error(response, "exchange OAuth").await;
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("401"));
        assert!(!diagnostic.contains(marker));
        server.abort();
    }
}
