// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3524: R2 read evidence for `lake_part_receipt_reconcile` on a LEAN
//! tenant, through the platform's lake-cell credential exchange.
//!
//! Lean tenants store no R2 credential: every cell process exchanges its own
//! short-lived, tenant-scoped one. The reconcile Job does the same. Its pod
//! presents a pod-bound projected ServiceAccount token (audience
//! [`RECONCILE_AUDIENCE`], ServiceAccount = the Job's own name) at
//!
//! ```text
//! POST {control_url}/v1/lake/cells/{cell_id}/receipt-reconcile-exchange
//! {"tenant_id": "<T>", "role": "receipt_reconcile", "accepts": ["lake_part_read"]}
//! ```
//!
//! the platform verifies the token by TokenReview, checks that the pod belongs to
//! the platform reconcile Job for T, and that T is still placed on that cell and
//! not fenced. It then mints exactly one credential: `lake_part_read`,
//! object-read-only, T's `lake/parts/v1/tenant=<T>/` prefix. This module
//! refuses any response that carries anything else, so the binary can only
//! read (GET and list) T's part tree. `--apply` still writes only to control
//! PostgreSQL.

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use zeroize::Zeroizing;

use crate::part_ingest::cell::{ExchangeRefused, ExchangeResponse};
use crate::part_ingest::s3_store::S3Location;

/// The exchange role. Never a cell role: no cell process can ask for it.
pub const RECONCILE_EXCHANGE_ROLE: &str = "receipt_reconcile";
/// The only class the reconcile accepts.
pub const RECONCILE_EXCHANGE_ACCEPTS: &[&str] = &["lake_part_read"];
/// The route leaf under `{control_url}/v1/lake/cells/{cell_id}/`.
pub const RECONCILE_EXCHANGE_LEAF: &str = nanosiem_lake_cell::contract::RECEIPT_RECONCILE_EXCHANGE_LEAF;
/// Audience of the Job's projected token. Distinct from the cells'
/// `nano-lake-cell`, so neither token is accepted at the other's route.
pub const RECONCILE_AUDIENCE: &str = nanosiem_lake_cell::contract::RECEIPT_RECONCILE_AUDIENCE;
/// Env: the full exchange URL (rendered by the platform).
pub const RECONCILE_EXCHANGE_URL_ENV: &str = "NANO_RECONCILE_EXCHANGE_URL";
/// Env: the projected token file.
pub const RECONCILE_TOKEN_FILE_ENV: &str = "NANO_RECONCILE_TOKEN_FILE";
/// A credential that expires sooner than this after the exchange is refused.
pub const RECONCILE_MIN_REMAINING: chrono::Duration = chrono::Duration::minutes(5);
/// The run stops this long before the credential expires.
pub const RECONCILE_EXPIRY_MARGIN: chrono::Duration = chrono::Duration::seconds(60);
/// A projected ServiceAccount JWT is about 1 KiB.
const MAX_TOKEN_BYTES: u64 = 8 * 1024;

/// The tenant's part tree, as the exchange scopes it.
pub fn parts_root(tenant: &str) -> String {
    format!("lake/parts/v1/tenant={tenant}/")
}

/// The read grant the reconcile runs on.
pub struct ReconcileReadGrant {
    /// The tenant bucket, unprefixed: the reconciler addresses full keys,
    /// all under [`parts_root`], which is all the credential can read.
    pub location: S3Location,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// `https://<host>[:port]/<base>/v1/lake/cells/<cell>/receipt-reconcile-exchange`,
/// with no userinfo, query or fragment.
pub fn validate_exchange_url(url: &str) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url).context("exchange URL does not parse")?;
    ensure!(parsed.scheme() == "https" || (cfg!(test) && parsed.scheme() == "http"), "exchange URL must be https");
    ensure!(parsed.username().is_empty() && parsed.password().is_none() && parsed.query().is_none()
        && parsed.fragment().is_none() && parsed.host_str().is_some(), "exchange URL must be a bare https URL");
    let segments: Vec<&str> = parsed.path_segments().context("exchange URL has no path")?.collect();
    let n = segments.len();
    ensure!(n >= 5 && segments[n - 5..n - 2] == ["v1", "lake", "cells"] && segments[n - 1] == RECONCILE_EXCHANGE_LEAF,
        "exchange URL must end in /v1/lake/cells/<cell>/{RECONCILE_EXCHANGE_LEAF}");
    let cell = segments[n - 2];
    ensure!(!cell.is_empty() && cell.len() <= 63 && cell.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "exchange URL names no valid cell id");
    Ok(parsed)
}

/// Read the projected token: small, text, non-empty.
pub fn read_token_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let size = std::fs::metadata(path).with_context(|| format!("token file {}", path.display()))?.len();
    ensure!(size > 0 && size <= MAX_TOKEN_BYTES, "token file is empty or too large");
    let token = Zeroizing::new(std::fs::read_to_string(path).context("token file is not text")?);
    let trimmed = token.trim();
    ensure!(!trimmed.is_empty() && !trimmed.chars().any(char::is_whitespace), "token file holds no token");
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Validate the exchange response: exactly the read-only `lake_part_read`
/// credential for this tenant's own bucket and part tree, nothing else.
pub fn grant_from(exchange: ExchangeResponse, tenant: &str, now: chrono::DateTime<chrono::Utc>) -> Result<ReconcileReadGrant> {
    ensure!(exchange.schema_version == 1 && exchange.tenant_id == tenant && exchange.role == RECONCILE_EXCHANGE_ROLE,
        "exchange response binding differs");
    ensure!(exchange.owner_write.is_none() && exchange.owner_sign.is_none() && exchange.prevalence_owner.is_none()
        && exchange.notices.is_none() && exchange.edge_log_consumer_token.is_none() && exchange.edge_log_consumer_endpoint.is_none()
        && exchange.lake_part_delete_grant.is_none() && exchange.lake_part_gc.is_none(),
        "reconcile exchange carries a grant the reconcile must not hold");
    let [credential] = exchange.credentials.as_slice() else {
        bail!("reconcile exchange must return exactly one credential");
    };
    ensure!(credential.credential_class == "lake_part_read" && credential.permission == "object-read-only"
        && credential.prefixes == [parts_root(tenant)],
        "reconcile credential must be the read-only lake_part_read class on the tenant's part tree");
    ensure!(credential.bucket == format!("nano-shared-r2-{tenant}"), "reconcile credential names another bucket");
    if !cfg!(test) {
        crate::writer_reclaim::validate_r2_endpoint(&credential.endpoint)?;
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(&credential.expires_at)
        .context("reconcile credential expires_at")?.with_timezone(&chrono::Utc);
    ensure!(expires_at - now >= RECONCILE_MIN_REMAINING, "reconcile credential expires within {} minutes",
        RECONCILE_MIN_REMAINING.num_minutes());
    Ok(ReconcileReadGrant { location: crate::part_ingest::cell::location_of(credential), expires_at })
}

/// Exchange the Job's projected token for the reconcile read grant.
pub async fn exchange(url: &str, token: &str, tenant: &str) -> Result<ReconcileReadGrant> {
    let url = validate_exchange_url(url)?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "tenant_id": tenant, "role": RECONCILE_EXCHANGE_ROLE, "accepts": RECONCILE_EXCHANGE_ACCEPTS }))
        .send()
        .await
        .context("reconcile credential exchange")?;
    let status = response.status();
    if !status.is_success() {
        // The refusal code is not a secret (`tenant_not_placed`, `tenant_fenced`, ...).
        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let code = body["error"].as_str().unwrap_or("").chars().take(64).collect::<String>();
        return Err(anyhow::Error::new(ExchangeRefused::new(status.as_u16()))
            .context(format!("reconcile credential exchange refused: HTTP {} {code}", status.as_u16())));
    }
    let body = Zeroizing::new(response.bytes().await?.to_vec());
    let exchange: ExchangeResponse = serde_json::from_slice(&body).context("reconcile credential exchange response")?;
    grant_from(exchange, tenant, chrono::Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";

    fn response(expires: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        json!({"schema_version": 1, "tenant_id": T, "role": "receipt_reconcile", "credentials": [{
            "credential_class": "lake_part_read", "endpoint": "https://objects.invalid", "region": "auto",
            "bucket": format!("nano-shared-r2-{T}"), "permission": "object-read-only", "prefixes": [parts_root(T)],
            "access_key_id": "a", "secret_access_key": "s", "session_token": "t", "expires_at": expires.to_rfc3339()}]})
    }

    fn grant(value: serde_json::Value) -> Result<ReconcileReadGrant> {
        grant_from(serde_json::from_value(value).unwrap(), T, chrono::Utc::now())
    }

    #[test]
    fn accepts_exactly_the_read_only_part_tree_credential() {
        let at = chrono::Utc::now() + chrono::Duration::minutes(35);
        let g = grant(response(at)).unwrap();
        assert_eq!(g.location.bucket, format!("nano-shared-r2-{T}"));
        assert_eq!(g.location.prefix, "");
        assert_eq!(g.location.session_token.as_deref(), Some("t"));
        assert!((g.expires_at - at).num_seconds().abs() <= 1);
    }

    #[test]
    fn refuses_anything_beyond_the_read_grant() {
        let ok = response(chrono::Utc::now() + chrono::Duration::minutes(35));
        let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
        let mut v = ok.clone(); v["role"] = json!("query"); cases.push(("role", v));
        let mut v = ok.clone(); v["tenant_id"] = json!("7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00"); cases.push(("tenant", v));
        let mut v = ok.clone(); v["credentials"][0]["permission"] = json!("object-read-write"); cases.push(("write", v));
        let mut v = ok.clone(); v["credentials"][0]["credential_class"] = json!("lake_part"); cases.push(("class", v));
        let mut v = ok.clone(); v["credentials"][0]["prefixes"] = json!([]); cases.push(("bucket-wide", v));
        let mut v = ok.clone(); v["credentials"][0]["prefixes"] = json!([format!("{}log/", parts_root(T))]); cases.push(("prefix", v));
        let mut v = ok.clone(); v["credentials"][0]["bucket"] = json!("nano-shared-r2-other"); cases.push(("bucket", v));
        let mut v = ok.clone(); let extra = v["credentials"][0].clone(); v["credentials"].as_array_mut().unwrap().push(extra);
        cases.push(("two credentials", v));
        let mut v = ok.clone(); v["credentials"] = json!([]); cases.push(("none", v));
        let mut v = ok.clone(); v["owner_sign"] = json!({"token": "x", "audience": "owner", "scope": "lake-parts:sign"});
        cases.push(("owner_sign", v));
        let mut v = ok.clone(); v["lake_part_gc"] = json!({}); cases.push(("lake_part_gc", v));
        let mut v = ok.clone(); v["lake_part_delete_grant"] = json!({}); cases.push(("delete grant", v));
        let mut v = ok.clone(); v["edge_log_consumer_token"] = json!("x"); cases.push(("edge log", v));
        cases.push(("expiring", response(chrono::Utc::now() + chrono::Duration::minutes(4))));
        for (name, value) in cases {
            assert!(grant(value).is_err(), "{name} must be refused");
        }
    }

    #[test]
    fn exchange_url_shape() {
        assert!(validate_exchange_url("https://api.nano.rs/api/v1/lake/cells/cell-a1/receipt-reconcile-exchange").is_ok());
        for bad in [
            "https://api.nano.rs/api/v1/lake/cells/cell-a1/credential-exchange",
            "https://u:p@api.nano.rs/api/v1/lake/cells/cell-a1/receipt-reconcile-exchange",
            "https://api.nano.rs/api/v1/lake/cells/cell-a1/receipt-reconcile-exchange?x=1",
            "https://api.nano.rs/api/v1/lake/cells/Cell_1/receipt-reconcile-exchange",
            "https://api.nano.rs/receipt-reconcile-exchange",
            "ftp://api.nano.rs/api/v1/lake/cells/cell-a1/receipt-reconcile-exchange",
        ] {
            assert!(validate_exchange_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_file_must_hold_one_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "a.b.c\n").unwrap();
        assert_eq!(read_token_file(&path).unwrap().as_str(), "a.b.c");
        std::fs::write(&path, "").unwrap();
        assert!(read_token_file(&path).is_err());
        std::fs::write(&path, "a b").unwrap();
        assert!(read_token_file(&path).is_err());
        assert!(read_token_file(&dir.path().join("missing")).is_err());
    }

    #[tokio::test]
    async fn exchange_sends_the_projected_token_and_declares_only_the_read_class() {
        let body = response(chrono::Utc::now() + chrono::Duration::minutes(35));
        let app = axum::Router::new().route("/api/v1/lake/cells/cell-a1/receipt-reconcile-exchange",
            axum::routing::post(move |headers: axum::http::HeaderMap, axum::Json(request): axum::Json<serde_json::Value>| {
                let body = body.clone();
                async move {
                    assert_eq!(headers.get(axum::http::header::AUTHORIZATION).unwrap(), "Bearer sa.jwt.token");
                    assert_eq!(request, json!({"tenant_id": T, "role": "receipt_reconcile", "accepts": ["lake_part_read"]}));
                    axum::Json(body)
                }
            }))
            .route("/api/v1/lake/cells/cell-b2/receipt-reconcile-exchange", axum::routing::post(|| async {
                (axum::http::StatusCode::FORBIDDEN, axum::Json(json!({"error": "tenant_not_placed"})))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = |cell: &str| format!("http://{addr}/api/v1/lake/cells/{cell}/{RECONCILE_EXCHANGE_LEAF}");
        let granted = exchange(&url("cell-a1"), "sa.jwt.token", T).await.unwrap();
        assert_eq!(granted.location.access_key_id, "a");
        let refused = exchange(&url("cell-b2"), "sa.jwt.token", T).await.err().unwrap();
        assert_eq!(refused.downcast_ref::<ExchangeRefused>().map(|r| r.status), Some(403));
        assert!(format!("{refused:#}").contains("tenant_not_placed"));
        server.abort();
    }

    /// The lake-cell feature `part_receipt_reconcile_cell_exchange_v1` is
    /// this module: the role, class, route leaf and audience the platform pins.
    #[test]
    fn cell_feature_part_receipt_reconcile_cell_exchange_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"part_receipt_reconcile_cell_exchange_v1"));
        assert_eq!((RECONCILE_EXCHANGE_LEAF, RECONCILE_AUDIENCE), ("receipt-reconcile-exchange", "nano-lake-receipt-reconcile"));
        assert_eq!((RECONCILE_EXCHANGE_ROLE, RECONCILE_EXCHANGE_ACCEPTS), ("receipt_reconcile", &["lake_part_read"][..]));
    }
}
