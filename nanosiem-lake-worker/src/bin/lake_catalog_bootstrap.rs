// SPDX-License-Identifier: AGPL-3.0-or-later

//! Idempotently provision Nano's machine identity and Lakekeeper warehouse.

use anyhow::{Context, Result, bail};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;

const MAX_ERROR_BODY: usize = 4_096;

struct Arguments {
    hydra_admin_uri: String,
    hydra_token_uri: String,
    client_id: String,
    client_secret: String,
    runtime_client_id: String,
    runtime_client_secret: String,
    scope: String,
    audience: String,
    catalog_management_uri: String,
    warehouse_config: PathBuf,
    storage_access_key: Option<String>,
    storage_secret_key: Option<String>,
    allow_insecure_http: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct ServerInfo {
    bootstrapped: bool,
    #[serde(rename = "authz-backend")]
    authz_backend: String,
}

#[derive(Deserialize)]
struct WarehouseList {
    warehouses: Vec<Value>,
}

struct WarehouseIdentity {
    id: String,
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let arguments = Arguments::parse(std::env::args().skip(1))?;
    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    ensure_hydra_client(
        &client,
        &arguments,
        &arguments.client_id,
        &arguments.client_secret,
        "Nano Lakekeeper operator",
    )
    .await?;
    ensure_hydra_client(
        &client,
        &arguments,
        &arguments.runtime_client_id,
        &arguments.runtime_client_secret,
        "Nano Lakekeeper runtime",
    )
    .await?;
    let operator_token = fetch_token(
        &client,
        &arguments,
        &arguments.client_id,
        &arguments.client_secret,
    )
    .await?;
    let bootstrapped =
        ensure_catalog_bootstrapped(&client, &arguments, &operator_token).await?;
    let warehouse = ensure_warehouse(&client, &arguments, &operator_token).await?;
    ensure_runtime_warehouse_grant(&client, &arguments, &operator_token, &warehouse).await?;
    let runtime_token = fetch_token(
        &client,
        &arguments,
        &arguments.runtime_client_id,
        &arguments.runtime_client_secret,
    )
    .await?;
    verify_runtime_warehouse_access(&client, &arguments, &runtime_token, &warehouse).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "ready",
            "operator_identity": arguments.client_id,
            "runtime_identity": arguments.runtime_client_id,
            "catalog_bootstrapped": bootstrapped,
            "warehouse": warehouse.name,
            "warehouse_id": warehouse.id,
        }))?
    );
    Ok(())
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> Result<Self> {
        let mut map = std::collections::BTreeMap::new();
        let mut allow_insecure_http = false;
        while let Some(argument) = values.next() {
            if argument == "--allow-insecure-http" {
                allow_insecure_http = true;
                continue;
            }
            let value = values
                .next()
                .with_context(|| format!("{argument} requires a value"))?;
            if map.insert(argument.clone(), value).is_some() {
                bail!("duplicate argument: {argument}");
            }
        }
        let take = |map: &mut std::collections::BTreeMap<String, String>, key: &str| {
            map.remove(key).with_context(|| format!("{key} is required"))
        };
        let client_secret_env = take(&mut map, "--client-secret-env")?;
        validate_environment_name(&client_secret_env)?;
        let runtime_client_secret_env = take(&mut map, "--runtime-client-secret-env")?;
        validate_environment_name(&runtime_client_secret_env)?;
        let storage_access_key_env = map.remove("--storage-access-key-env");
        let storage_secret_key_env = map.remove("--storage-secret-key-env");
        if storage_access_key_env.is_some() != storage_secret_key_env.is_some() {
            bail!(
                "--storage-access-key-env and --storage-secret-key-env must be provided together"
            );
        }
        if let Some(name) = storage_access_key_env.as_deref() {
            validate_environment_name(name)?;
        }
        if let Some(name) = storage_secret_key_env.as_deref() {
            validate_environment_name(name)?;
        }
        let result = Self {
            hydra_admin_uri: take(&mut map, "--hydra-admin-uri")?,
            hydra_token_uri: take(&mut map, "--hydra-token-uri")?,
            client_id: take(&mut map, "--client-id")?,
            client_secret: std::env::var(&client_secret_env)
                .with_context(|| format!("environment variable {client_secret_env} is required"))?,
            runtime_client_id: take(&mut map, "--runtime-client-id")?,
            runtime_client_secret: std::env::var(&runtime_client_secret_env).with_context(|| {
                format!("environment variable {runtime_client_secret_env} is required")
            })?,
            scope: take(&mut map, "--scope")?,
            audience: take(&mut map, "--audience")?,
            catalog_management_uri: take(&mut map, "--catalog-management-uri")?,
            warehouse_config: PathBuf::from(take(&mut map, "--warehouse-config")?),
            storage_access_key: storage_access_key_env
                .as_deref()
                .map(std::env::var)
                .transpose()
                .context("storage access-key environment variable is required")?,
            storage_secret_key: storage_secret_key_env
                .as_deref()
                .map(std::env::var)
                .transpose()
                .context("storage secret-key environment variable is required")?,
            allow_insecure_http,
        };
        if !map.is_empty() {
            bail!(
                "unknown arguments: {}",
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("client ID", self.client_id.as_str()),
            ("runtime client ID", self.runtime_client_id.as_str()),
            ("OAuth scope", self.scope.as_str()),
            ("OAuth audience", self.audience.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 256
                || !value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._:/-".contains(character))
            {
                bail!("{name} is invalid");
            }
        }
        if self.runtime_client_id == self.client_id {
            bail!("operator and runtime client IDs must be distinct");
        }
        for (name, secret) in [
            ("operator OAuth client secret", self.client_secret.as_str()),
            (
                "runtime OAuth client secret",
                self.runtime_client_secret.as_str(),
            ),
        ] {
            if !(32..=4_096).contains(&secret.len()) || secret.chars().any(char::is_control) {
                bail!("{name} must contain 32-4096 non-control characters");
            }
        }
        if let Some(access_key) = self.storage_access_key.as_deref() {
            if access_key.is_empty()
                || access_key.len() > 1_024
                || access_key.chars().any(char::is_control)
            {
                bail!("storage access key must contain 1-1024 non-control characters");
            }
        }
        if let Some(secret_key) = self.storage_secret_key.as_deref() {
            if secret_key.is_empty()
                || secret_key.len() > 4_096
                || secret_key.chars().any(char::is_control)
            {
                bail!("storage secret key must contain 1-4096 non-control characters");
            }
        }
        for (name, uri) in [
            ("Hydra admin URI", self.hydra_admin_uri.as_str()),
            ("Hydra token URI", self.hydra_token_uri.as_str()),
            ("catalog management URI", self.catalog_management_uri.as_str()),
        ] {
            if uri.len() > 2_048 || uri.chars().any(char::is_control) {
                bail!("{name} is invalid");
            }
            if !uri.starts_with("https://")
                && !(self.allow_insecure_http && uri.starts_with("http://"))
            {
                bail!("{name} must use HTTPS unless --allow-insecure-http is explicit");
            }
        }
        if !self.warehouse_config.is_absolute() {
            bail!("--warehouse-config must be an absolute path");
        }
        Ok(())
    }
}

fn validate_environment_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        bail!("--client-secret-env must name one bounded environment variable");
    }
    Ok(())
}

fn hydra_client_registration(
    client_id: &str,
    client_secret: &str,
    client_name: &str,
    arguments: &Arguments,
) -> Value {
    json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "grant_types": ["client_credentials"],
        "response_types": ["token"],
        "scope": arguments.scope,
        "audience": [arguments.audience],
        "access_token_strategy": "jwt",
        "token_endpoint_auth_method": "client_secret_post",
    })
}

async fn ensure_hydra_client(
    client: &Client,
    arguments: &Arguments,
    client_id: &str,
    client_secret: &str,
    client_name: &str,
) -> Result<()> {
    let endpoint = format!(
        "{}/admin/clients/{}",
        arguments.hydra_admin_uri.trim_end_matches('/'),
        client_id
    );
    let response = client.get(&endpoint).send().await?;
    match response.status() {
        StatusCode::OK => {
            let existing: Value = response.json().await?;
            let contract_matches = existing["grant_types"] == json!(["client_credentials"])
                && existing["response_types"] == json!(["token"])
                && existing["scope"] == arguments.scope
                && existing["audience"] == json!([arguments.audience])
                && existing["access_token_strategy"] == "jwt"
                && existing["token_endpoint_auth_method"] == "client_secret_post";
            // Hydra never returns a stored client secret, so equality cannot
            // prove that the configured secret is current. Re-apply the exact
            // managed registration on every bootstrap run. This makes secret
            // rotation deterministic instead of silently retaining an old
            // credential merely because the public fields still match.
            if !contract_matches {
                tracing::info!(client_id, "repairing Hydra client contract");
            }
            checked(
                client
                    .put(&endpoint)
                    .json(&hydra_client_registration(
                        client_id,
                        client_secret,
                        client_name,
                        arguments,
                    ))
                    .send()
                    .await?,
                "update Hydra client",
            )
            .await?;
        }
        StatusCode::NOT_FOUND => {
            checked(
                client
                    .post(format!(
                        "{}/admin/clients",
                        arguments.hydra_admin_uri.trim_end_matches('/')
                    ))
                    .json(&hydra_client_registration(
                        client_id,
                        client_secret,
                        client_name,
                        arguments,
                    ))
                    .send()
                    .await?,
                "create Hydra client",
            )
            .await?;
        }
        _ => {
            checked(response, "inspect Hydra client").await?;
        }
    }
    Ok(())
}

async fn fetch_token(
    client: &Client,
    arguments: &Arguments,
    client_id: &str,
    client_secret: &str,
) -> Result<String> {
    let response = checked(
        client
            .post(&arguments.hydra_token_uri)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", arguments.scope.as_str()),
                ("audience", arguments.audience.as_str()),
            ])
            .send()
            .await?,
        "obtain Hydra workload token",
    )
    .await?;
    let token: TokenResponse = response.json().await?;
    if token.access_token.len() < 32 || token.access_token.chars().any(char::is_control) {
        bail!("Hydra returned an invalid workload token");
    }
    Ok(token.access_token)
}

async fn ensure_catalog_bootstrapped(
    client: &Client,
    arguments: &Arguments,
    token: &str,
) -> Result<bool> {
    let base = arguments.catalog_management_uri.trim_end_matches('/');
    let mut info: ServerInfo = checked(
        client
            .get(format!("{base}/management/v1/info"))
            .bearer_auth(token)
            .send()
            .await?,
        "inspect Lakekeeper server",
    )
    .await?
    .json()
    .await?;
    if !info.bootstrapped {
        checked(
            client
                .post(format!("{base}/management/v1/bootstrap"))
                .bearer_auth(token)
                .json(&json!({
                    "accept-terms-of-use": true,
                    "is-operator": true,
                    "user-name": "Nano Lakekeeper workload",
                }))
                .send()
                .await?,
            "bootstrap Lakekeeper",
        )
        .await?;
        info = checked(
            client
                .get(format!("{base}/management/v1/info"))
                .bearer_auth(token)
                .send()
                .await?,
            "verify Lakekeeper bootstrap",
        )
        .await?
        .json()
        .await?;
    }
    if !info.bootstrapped {
        bail!("Lakekeeper did not report bootstrapped state");
    }
    if info.authz_backend != "openfga" {
        bail!(
            "Lakekeeper must use the OpenFGA authorization backend, found {}",
            info.authz_backend
        );
    }
    Ok(true)
}

async fn ensure_warehouse(
    client: &Client,
    arguments: &Arguments,
    token: &str,
) -> Result<WarehouseIdentity> {
    let bytes = std::fs::read(&arguments.warehouse_config).with_context(|| {
        format!(
            "read warehouse configuration {}",
            arguments.warehouse_config.display()
        )
    })?;
    if bytes.len() > 1024 * 1024 {
        bail!("warehouse configuration exceeds 1 MiB");
    }
    let mut requested: Value =
        serde_json::from_slice(&bytes).context("parse warehouse configuration")?;
    if let (Some(access_key), Some(secret_key)) = (
        arguments.storage_access_key.as_deref(),
        arguments.storage_secret_key.as_deref(),
    ) {
        requested["storage-credential"] = json!({
            "type": "s3",
            "credential-type": "access-key",
            "access-key-id": access_key,
            "secret-access-key": secret_key,
        });
    }
    if requested["storage-credential"].is_null() {
        bail!(
            "warehouse configuration requires storage-credential or the two storage credential environment arguments"
        );
    }
    let name = requested["warehouse-name"]
        .as_str()
        .filter(|name| !name.is_empty() && name.len() <= 255)
        .context("warehouse-name is required")?;
    let base = arguments.catalog_management_uri.trim_end_matches('/');
    let list: WarehouseList = checked(
        client
            .get(format!("{base}/management/v1/warehouse"))
            .bearer_auth(token)
            .send()
            .await?,
        "list Lakekeeper warehouses",
    )
    .await?
    .json()
    .await?;
    if let Some(existing) = list
        .warehouses
        .iter()
        .find(|warehouse| warehouse["name"] == name)
    {
        for field in ["bucket", "key-prefix", "region", "endpoint"] {
            let current = &existing["storage-profile"][field];
            let desired = &requested["storage-profile"][field];
            let matches = if field == "endpoint" {
                current.as_str().map(|value| value.trim_end_matches('/'))
                    == desired.as_str().map(|value| value.trim_end_matches('/'))
            } else {
                current == desired
            };
            if !matches {
                bail!("existing warehouse {name} has a different storage-profile.{field}");
            }
        }
        let id = existing["id"]
            .as_str()
            .context("existing warehouse has no ID")?;
        return Ok(WarehouseIdentity {
            id: id.to_string(),
            name: name.to_string(),
        });
    }
    let created: Value = checked(
        client
            .post(format!("{base}/management/v1/warehouse"))
            .bearer_auth(token)
            .json(&requested)
            .send()
            .await?,
        "create Lakekeeper warehouse",
    )
    .await?
    .json()
    .await?;
    let id = created["warehouse-id"]
        .as_str()
        .context("created warehouse response has no warehouse-id")?;
    Ok(WarehouseIdentity {
        id: id.to_string(),
        name: name.to_string(),
    })
}

async fn ensure_runtime_warehouse_grant(
    client: &Client,
    arguments: &Arguments,
    operator_token: &str,
    warehouse: &WarehouseIdentity,
) -> Result<()> {
    let base = arguments.catalog_management_uri.trim_end_matches('/');
    let endpoint = format!(
        "{base}/management/v1/permissions/warehouse/{}/assignments",
        warehouse.id
    );
    let current: Value = checked(
        client
            .get(&endpoint)
            .bearer_auth(operator_token)
            .send()
            .await?,
        "inspect runtime identity warehouse grants",
    )
    .await?
    .json()
    .await?;
    let runtime_user = format!("oidc~{}", arguments.runtime_client_id);
    let assignments = current["assignments"]
        .as_array()
        .context("warehouse assignments response is invalid")?;
    let runtime_grants = assignments
        .iter()
        .filter(|assignment| assignment["user"].as_str() == Some(runtime_user.as_str()))
        .filter_map(|assignment| assignment["type"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if runtime_grants
        .iter()
        .any(|grant| !matches!(*grant, "create" | "modify"))
    {
        bail!("runtime identity has an unexpected warehouse privilege");
    }
    let missing = ["create", "modify"]
        .into_iter()
        .filter(|grant| !runtime_grants.contains(grant))
        .map(|grant| json!({ "type": grant, "user": runtime_user }))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    checked(
        client
            .post(endpoint)
            .bearer_auth(operator_token)
            .json(&json!({
                "writes": missing,
                "deletes": [],
            }))
            .send()
            .await?,
        "grant runtime identity warehouse access",
    )
    .await?;
    Ok(())
}

async fn verify_runtime_warehouse_access(
    client: &Client,
    arguments: &Arguments,
    runtime_token: &str,
    warehouse: &WarehouseIdentity,
) -> Result<()> {
    let base = arguments.catalog_management_uri.trim_end_matches('/');
    let list: WarehouseList = checked(
        client
            .get(format!("{base}/management/v1/warehouse"))
            .bearer_auth(runtime_token)
            .send()
            .await?,
        "verify runtime warehouse access",
    )
    .await?
    .json()
    .await?;
    let visible = list
        .warehouses
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect::<Vec<_>>();
    if visible != [warehouse.id.as_str()] {
        bail!(
            "runtime identity must see exactly its assigned warehouse, saw {}",
            visible.len()
        );
    }
    Ok(())
}

async fn checked(response: Response, operation: &str) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let body = body.chars().take(MAX_ERROR_BODY).collect::<String>();
    bail!("{operation} failed with {status}: {body}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_endpoints_require_an_explicit_flag() {
        unsafe {
            std::env::set_var(
                "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET",
                "one-local-secret-that-is-long-enough",
            );
        }
        let base = [
            "--hydra-admin-uri", "http://127.0.0.1:24445", "--hydra-token-uri",
            "http://127.0.0.1:24444/oauth2/token", "--client-id", "nano-lakekeeper",
            "--client-secret-env", "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET",
            "--runtime-client-id", "nano-lakekeeper-runtime", "--runtime-client-secret-env",
            "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET", "--scope", "lakekeeper", "--audience",
            "lakekeeper", "--catalog-management-uri",
            "http://127.0.0.1:28184", "--warehouse-config", "/tmp/warehouse.json",
        ];
        assert!(Arguments::parse(base.into_iter().map(str::to_string)).is_err());
        let parsed = Arguments::parse(
            base.into_iter()
                .chain(["--allow-insecure-http"])
                .map(str::to_string),
        )
        .unwrap();
        assert_eq!(parsed.audience, "lakekeeper");
    }

    #[test]
    fn storage_credentials_are_read_only_from_a_named_pair() {
        // Self-contained: under cargo-nextest every test is its own process,
        // so it cannot rely on the test above having set the client secret.
        unsafe {
            std::env::set_var(
                "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET",
                "one-local-secret-that-is-long-enough",
            );
            std::env::set_var("NANO_TEST_LAKE_ACCESS_KEY", "local-access-key");
            std::env::set_var("NANO_TEST_LAKE_SECRET_KEY", "local-secret-key");
        }
        let base = [
            "--hydra-admin-uri", "http://127.0.0.1:24445", "--hydra-token-uri",
            "http://127.0.0.1:24444/oauth2/token", "--client-id", "nano-lakekeeper",
            "--client-secret-env", "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET",
            "--runtime-client-id", "nano-lakekeeper-runtime", "--runtime-client-secret-env",
            "NANO_TEST_LAKEKEEPER_BOOTSTRAP_SECRET", "--scope", "lakekeeper", "--audience",
            "lakekeeper", "--catalog-management-uri", "http://127.0.0.1:28184",
            "--warehouse-config", "/tmp/warehouse.json", "--storage-access-key-env",
            "NANO_TEST_LAKE_ACCESS_KEY", "--storage-secret-key-env",
            "NANO_TEST_LAKE_SECRET_KEY", "--allow-insecure-http",
        ];
        let parsed = Arguments::parse(base.into_iter().map(str::to_string)).unwrap();
        assert_eq!(parsed.storage_access_key.as_deref(), Some("local-access-key"));
        assert_eq!(parsed.storage_secret_key.as_deref(), Some("local-secret-key"));

        let missing_pair = base
            .into_iter()
            .filter(|value| *value != "--storage-secret-key-env" && *value != "NANO_TEST_LAKE_SECRET_KEY")
            .map(str::to_string);
        assert!(Arguments::parse(missing_pair).is_err());
    }
}
