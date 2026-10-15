// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared provider proofs for operator and scheduled reconciliation.
use anyhow::{bail, Context, Result};
use chrono::Utc;
use futures::TryStreamExt;
use opendal::{services::S3, ErrorKind, Operator};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
/// The R2 S3 endpoint from the AWS-style environment the reconciliation
/// workloads mount (`AWS_ENDPOINT_URL_S3`, then `AWS_ENDPOINT_URL`, then
/// `NANO_LAKE_SHARED_R2_READ_ENDPOINT`), validated by [`validate_r2_endpoint`].
pub fn r2_endpoint_from_env() -> Result<String> {
    let endpoint = std::env::var("AWS_ENDPOINT_URL_S3")
        .or_else(|_| std::env::var("AWS_ENDPOINT_URL"))
        .or_else(|_| std::env::var("NANO_LAKE_SHARED_R2_READ_ENDPOINT"))
        .context("AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL is required")?;
    validate_r2_endpoint(&endpoint)?;
    Ok(endpoint)
}

/// A bare HTTPS `*.r2.cloudflarestorage.com` origin: no userinfo, path,
/// query or fragment.
pub fn validate_r2_endpoint(endpoint: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(endpoint)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || !parsed
            .host_str()
            .is_some_and(|host| host.ends_with(".r2.cloudflarestorage.com"))
    {
        bail!("R2 endpoint must be a bare HTTPS *.r2.cloudflarestorage.com origin");
    }
    Ok(())
}

pub fn r2_operator(bucket: &str) -> Result<(Operator, String)> {
    let endpoint = r2_endpoint_from_env()?;
    let mut builder = S3::default()
        .bucket(bucket)
        .endpoint(&endpoint)
        .region(&std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()))
        .access_key_id(&std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID required")?)
        .secret_access_key(
            &std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY required")?,
        )
        .disable_config_load()
        .disable_ec2_metadata();
    if let Ok(token) = std::env::var("AWS_SESSION_TOKEN") {
        builder = builder.session_token(&token);
    }
    Ok((Operator::new(builder)?.finish(), endpoint))
}

pub async fn prove_absent(operator: &Operator, key: &str) -> Result<()> {
    // NotFound alone could mean a missing bucket. A bounded list also proves
    // that this credential can access the bucket; 403/timeout never proves absence.
    match tokio::time::timeout(std::time::Duration::from_secs(30), operator.stat(key)).await? {
        Ok(_) => bail!("R2 HEAD found the object; extension refused"),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("R2 HEAD did not prove object absence"),
    }
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut entries = operator.lister_with("").limit(1).await?;
        let _ = entries.try_next().await?;
        Ok::<_, opendal::Error>(())
    })
    .await??;
    Ok(())
}

pub async fn absence_evidence(operator: &Operator, row: &Value, endpoint: &str) -> Result<Value> {
    let key = row["object_key"].as_str().context("missing key")?;
    prove_absent(operator, key).await?;
    let mut evidence = json!({
        "writer_reservation_id": row["writer_reservation_id"],
        "bucket": row["object_bucket"], "key": key, "endpoint": endpoint,
        "object_absent": true, "head_status": 404, "bucket_accessible": true,
        "observed_at": Utc::now().to_rfc3339(),
    });
    evidence["proof_sha256"] = hex::encode(Sha256::digest(serde_json::to_vec(&evidence)?)).into();
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::validate_r2_endpoint;

    #[test]
    fn r2_endpoint_must_be_a_bare_https_r2_origin() {
        assert!(validate_r2_endpoint(
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
        )
        .is_ok());
        assert!(validate_r2_endpoint(
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/"
        )
        .is_ok());
        for bad in [
            "http://a.r2.cloudflarestorage.com",
            "https://a.r2.cloudflarestorage.com/bucket",
            "https://user:pw@a.r2.cloudflarestorage.com",
            "https://a.r2.cloudflarestorage.com/?x=1",
            "https://a.r2.cloudflarestorage.com.evil.example",
            "https://s3.amazonaws.com",
            "not a url",
        ] {
            assert!(validate_r2_endpoint(bad).is_err(), "{bad} must be refused");
        }
    }
}
