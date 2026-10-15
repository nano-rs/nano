// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hydrate the current Iceberg snapshot by exact S3 object version in Rust.

use anyhow::{Context, Result, bail};
use nanosiem_lake_worker::generation::hydrate_current_snapshot;
use nanosiem_lake_worker::iceberg::{CatalogConfig, table_ident};
use std::path::PathBuf;

struct Arguments {
    table: String,
    table_location_prefix: String,
    catalog: CatalogConfig,
    output_root: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let args = Arguments::parse(std::env::args().skip(1))?;
    let catalog = args.catalog.load().await?;
    let table_id = table_ident(&args.table)?;
    let result = hydrate_current_snapshot(
        &catalog,
        &args.catalog,
        &table_id,
        &args.table_location_prefix,
        &args.output_root,
    )
    .await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> Result<Self> {
        let mut map = std::collections::BTreeMap::new();
        let mut vended_credentials = false;
        let mut s3_default_credentials = false;
        let mut s3_path_style_access = true;
        let mut allow_anonymous_catalog = false;
        while let Some(argument) = values.next() {
            if argument == "--vended-credentials" {
                vended_credentials = true;
                continue;
            }
            if argument == "--s3-default-credentials" {
                s3_default_credentials = true;
                continue;
            }
            if argument == "--s3-virtual-host-style" {
                s3_path_style_access = false;
                continue;
            }
            if argument == "--allow-anonymous-catalog" {
                allow_anonymous_catalog = true;
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
        let required_env = |name: String, flag: &str| -> Result<String> {
            if name.is_empty()
                || name.len() > 256
                || !name
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '_')
            {
                bail!("{flag} must name one bounded environment variable");
            }
            std::env::var(&name)
                .with_context(|| format!("environment variable {name} is required"))
        };
        let table_location_prefix = take(&mut map, "--table-location-prefix")?;
        if !table_location_prefix.starts_with("s3://") || table_location_prefix.len() > 2_048 {
            bail!("--table-location-prefix must be one bounded s3:// prefix");
        }
        let credential_env = map.remove("--catalog-credential-env");
        let catalog_token_file = map
            .remove("--catalog-token-file")
            .map(PathBuf::from);
        let access_env = map.remove("--s3-access-key-env");
        let secret_env = map.remove("--s3-secret-key-env");
        let session_token = map
            .remove("--s3-session-token-env")
            .map(|name| required_env(name, "--s3-session-token-env"))
            .transpose()?;
        let (s3_access_key, s3_secret_key) = if s3_default_credentials {
            if access_env.is_some() || secret_env.is_some() || session_token.is_some() {
                bail!("--s3-default-credentials cannot be combined with static credential flags");
            }
            (String::new(), String::new())
        } else {
            (
                required_env(
                    access_env.context("--s3-access-key-env is required")?,
                    "--s3-access-key-env",
                )?,
                required_env(
                    secret_env.context("--s3-secret-key-env is required")?,
                    "--s3-secret-key-env",
                )?,
            )
        };
        let result = Self {
            table: take(&mut map, "--table")?,
            table_location_prefix,
            catalog: CatalogConfig {
                uri: take(&mut map, "--catalog-uri")?,
                warehouse: take(&mut map, "--warehouse")?,
                credential: credential_env
                    .map(|name| required_env(name, "--catalog-credential-env"))
                    .transpose()?,
                token_file: catalog_token_file,
                oauth_scope: map.remove("--catalog-oauth-scope"),
                oauth_audience: map.remove("--catalog-oauth-audience"),
                oauth_server_uri: map.remove("--catalog-oauth-server-uri"),
                realm: map.remove("--catalog-realm"),
                allow_anonymous: allow_anonymous_catalog,
                s3_endpoint: map.remove("--s3-endpoint").unwrap_or_default(),
                s3_region: map
                    .remove("--s3-region")
                    .unwrap_or_else(|| "us-east-1".to_string()),
                s3_access_key,
                s3_secret_key,
                s3_session_token: session_token,
                s3_path_style_access,
                s3_default_credentials,
                vended_credentials,
            },
            output_root: PathBuf::from(take(&mut map, "--output-root")?),
        };
        if !map.is_empty() {
            bail!(
                "unknown arguments: {}",
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydration_arguments_require_credentials_by_environment_name() {
        unsafe {
            std::env::set_var("NANO_HYDRATE_CATALOG", "client:secret");
            std::env::set_var("NANO_HYDRATE_ACCESS", "access");
            std::env::set_var("NANO_HYDRATE_SECRET", "secret");
        }
        let parsed = Arguments::parse(
            [
                "--table", "nano.events", "--table-location-prefix", "s3://bucket/events",
                "--catalog-uri", "http://localhost:8181", "--warehouse", "catalog",
                "--catalog-credential-env", "NANO_HYDRATE_CATALOG", "--s3-endpoint",
                "http://localhost:9000", "--s3-access-key-env", "NANO_HYDRATE_ACCESS",
                "--s3-secret-key-env", "NANO_HYDRATE_SECRET", "--output-root", "/tmp/snapshot",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(parsed.table, "nano.events");
        assert_eq!(parsed.output_root, PathBuf::from("/tmp/snapshot"));
        assert!(!parsed.catalog.s3_default_credentials);
    }

    #[test]
    fn hydration_arguments_accept_explicit_default_credential_chain() {
        unsafe {
            std::env::set_var("NANO_HYDRATE_DEFAULT_CATALOG", "client:secret");
        }
        let parsed = Arguments::parse(
            [
                "--table", "nano.events", "--table-location-prefix", "s3://bucket/events",
                "--catalog-uri", "https://catalog.example", "--warehouse", "catalog",
                "--catalog-credential-env", "NANO_HYDRATE_DEFAULT_CATALOG",
                "--s3-region", "us-east-2", "--s3-default-credentials",
                "--s3-virtual-host-style", "--output-root", "/tmp/snapshot-default",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert!(parsed.catalog.s3_default_credentials);
        assert!(!parsed.catalog.s3_path_style_access);
        assert!(parsed.catalog.s3_endpoint.is_empty());
        assert!(parsed.catalog.s3_access_key.is_empty());
    }

    #[test]
    fn anonymous_catalog_access_requires_the_explicit_local_flag() {
        unsafe {
            std::env::set_var("NANO_HYDRATE_ANON_ACCESS", "access");
            std::env::set_var("NANO_HYDRATE_ANON_SECRET", "secret");
        }
        let parsed = Arguments::parse(
            [
                "--table",
                "nano.events",
                "--table-location-prefix",
                "s3://bucket/events",
                "--catalog-uri",
                "http://127.0.0.1:8181/catalog",
                "--warehouse",
                "local",
                "--allow-anonymous-catalog",
                "--s3-endpoint",
                "http://127.0.0.1:9000",
                "--s3-access-key-env",
                "NANO_HYDRATE_ANON_ACCESS",
                "--s3-secret-key-env",
                "NANO_HYDRATE_ANON_SECRET",
                "--output-root",
                "/tmp/snapshot-anonymous",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert!(parsed.catalog.credential.is_none());
        assert!(parsed.catalog.allow_anonymous);
    }
}
