// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant scoped router credentials (NAN-3289, completes NAN-2904).
//!
//! The cluster-wide query token reaches every tenant on every cell. A
//! per-tenant token reaches exactly one tenant, on one cell, for one scope,
//! and the router checks it against the `/v1/tenants/{t}` path segment.
//!
//! Derivation (byte-exact; nanosiem-core `search::lake_cell` and the platform
//! `lake-cell-tenant-token.ts` implement the same, pinned by one golden
//! vector in all three):
//!
//! ```text
//! tenant_key = HMAC-SHA256(key = full router token, "nano-cell-router-tenant-key/v1")
//! token      = "nct1." ‖ hex(HMAC-SHA256(key = tenant_key,
//!                  "v1" ‖ 0x00 ‖ tenant ‖ 0x00 ‖ cell id ‖ 0x00 ‖ scope))
//! ```
//!
//! `tenant_key` is the "derivation capability": the shared services
//! (search / api / jobs) that serve every tenant hold it (it cannot be turned
//! back into the full token), and the deployer materializes single-tenant
//! tokens from it for per-tenant pods (`nano-lean-job-runner-<T>` gets only
//! its tenant's `query` token and `job` key). Rotating the full token
//! rotates every derived token.
//!
//! Scopes: `query` (`/v1/tenants/{t}/query[/…]` and a query-role wake),
//! `detect` (`/v1/tenants/{t}/detect[/…]`), `status`
//! (`GET /v1/tenants/{t}/status`). `job` is never a bearer: it is the HMAC
//! key a durable-job dispatcher signs a `POST …/query/v1/jobs/search` body
//! with ([`sign_job_spec`]); the router verifies it before query[T] sees the
//! spec (P2-2).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Prefix of every per-tenant router token.
pub const TENANT_TOKEN_PREFIX: &str = "nct1.";
/// Domain of the tenant-key derivation from the full router token.
pub const TENANT_KEY_INFO: &[u8] = b"nano-cell-router-tenant-key/v1";
/// Domain of a durable-job spec signature.
pub const JOB_SPEC_DOMAIN: &[u8] = b"nano-cell-job-spec/v1";
/// Request header carrying the hex job-spec signature.
pub const JOB_SIGNATURE_HEADER: &str = "x-nano-cell-job-signature";
/// Header the router sets (and strips from callers) to tell query[T] how a
/// job spec was admitted: [`JOB_AUTH_SIGNED`] or [`JOB_AUTH_LEGACY`].
pub const JOB_AUTH_HEADER: &str = "x-nano-cell-job-auth";
pub const JOB_AUTH_SIGNED: &str = "signed";
/// Unsigned spec admitted while `router_accept_cluster_query_token` is on.
pub const JOB_AUTH_LEGACY: &str = "legacy";

/// What a per-tenant credential is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantScope {
    Query,
    Detect,
    Status,
    /// Job-spec signing key (never accepted as a bearer).
    Job,
}

impl TenantScope {
    pub const BEARERS: [TenantScope; 3] = [TenantScope::Query, TenantScope::Detect, TenantScope::Status];

    pub fn as_str(self) -> &'static str {
        match self {
            TenantScope::Query => "query",
            TenantScope::Detect => "detect",
            TenantScope::Status => "status",
            TenantScope::Job => "job",
        }
    }
}

fn mac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length")
}

/// The derivation capability (32 bytes).
#[derive(Clone)]
pub struct TenantKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for TenantKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TenantKey(..)")
    }
}

impl TenantKey {
    /// Derive from the full router token.
    pub fn from_router_token(full: &str) -> Self {
        let mut m = mac(full.as_bytes());
        m.update(TENANT_KEY_INFO);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&m.finalize().into_bytes());
        Self(key)
    }

    /// Parse the 64-hex form the deployer writes.
    pub fn from_hex(hex_key: &str) -> anyhow::Result<Self> {
        let bytes = Zeroizing::new(hex::decode(hex_key.trim()).map_err(|_| anyhow::anyhow!("router tenant key is not hex"))?);
        anyhow::ensure!(bytes.len() == 32, "router tenant key must be 32 bytes (64 hex)");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.0))
    }

    /// The credential for `tenant` on `cell_id` with `scope`.
    pub fn token(&self, tenant: &str, cell_id: &str, scope: TenantScope) -> Zeroizing<String> {
        let mut m = mac(&*self.0);
        m.update(b"v1");
        for part in [tenant.as_bytes(), cell_id.as_bytes(), scope.as_str().as_bytes()] {
            m.update(&[0]);
            m.update(part);
        }
        Zeroizing::new(format!("{TENANT_TOKEN_PREFIX}{}", hex::encode(m.finalize().into_bytes())))
    }

    /// Which bearer scope `presented` is for `tenant` on `cell_id`, compared
    /// in constant time against every bearer scope (no early exit).
    pub fn bearer_scope(&self, presented: &str, tenant: &str, cell_id: &str) -> Option<TenantScope> {
        let mut hit = None;
        for scope in TenantScope::BEARERS {
            let expected = self.token(tenant, cell_id, scope);
            if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
                hit = Some(scope);
            }
        }
        hit
    }

    /// Verify a job-spec signature made with this tenant's `job` key.
    pub fn verify_job_spec(&self, tenant: &str, cell_id: &str, body: &[u8], signature_hex: &str) -> bool {
        let key = self.token(tenant, cell_id, TenantScope::Job);
        let expected = sign_job_spec(&key, tenant, cell_id, body);
        bool::from(signature_hex.trim().as_bytes().ct_eq(expected.as_bytes()))
    }
}

/// Whether `presented` has the per-tenant token shape (never a cluster token).
pub fn is_tenant_token(presented: &str) -> bool {
    presented.starts_with(TENANT_TOKEN_PREFIX)
}

/// Sign a job-spec body with a tenant's `job` key (the dispatcher side).
pub fn sign_job_spec(job_key: &str, tenant: &str, cell_id: &str, body: &[u8]) -> String {
    let mut m = mac(job_key.as_bytes());
    m.update(JOB_SPEC_DOMAIN);
    for part in [tenant.as_bytes(), cell_id.as_bytes()] {
        m.update(&[0]);
        m.update(part);
    }
    m.update(&[0]);
    m.update(body);
    hex::encode(m.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden vector shared with nanosiem-core and the platform.
    pub(crate) const GOLDEN_FULL: &str = "full-router-token-0123456789abcdef0123456789";
    pub(crate) const GOLDEN_TENANT: &str = "0b7a2f9e-1c4d-4e8f-9a0b-1c2d3e4f5a6b";
    pub(crate) const GOLDEN_CELL: &str = "cell-us-d-0a1b2c3d";

    #[test]
    fn golden_vector() {
        let key = TenantKey::from_router_token(GOLDEN_FULL);
        assert_eq!(key.to_hex().as_str(), GOLDEN_KEY_HEX);
        assert_eq!(key.token(GOLDEN_TENANT, GOLDEN_CELL, TenantScope::Query).as_str(), GOLDEN_QUERY);
        assert_eq!(key.token(GOLDEN_TENANT, GOLDEN_CELL, TenantScope::Detect).as_str(), GOLDEN_DETECT);
        let job = key.token(GOLDEN_TENANT, GOLDEN_CELL, TenantScope::Job);
        assert_eq!(sign_job_spec(&job, GOLDEN_TENANT, GOLDEN_CELL, b"{}"), GOLDEN_JOB_SIG);
        assert_eq!(TenantKey::from_hex(GOLDEN_KEY_HEX).unwrap().to_hex().as_str(), GOLDEN_KEY_HEX);
    }

    const GOLDEN_KEY_HEX: &str = "8d4f3dc8d00c88091476a987ccb55bb1560f391439e73604e1dbec7c6575769c";
    const GOLDEN_QUERY: &str = "nct1.b268f7857708456bf5ed364d2429f318a9724795eb424a4329990dc55c6afb45";
    const GOLDEN_DETECT: &str = "nct1.6403019ba23c3a5992e509cc3f43a1237ed58e59fa26f0c57f71cc90e0b11d25";
    const GOLDEN_JOB_SIG: &str = "52c893cfc44f30cf484c0e42fd2d513178d30c53ce9189de4192a5b438a6bdd4";

    #[test]
    fn tokens_bind_tenant_cell_and_scope() {
        let key = TenantKey::from_router_token(GOLDEN_FULL);
        let q = key.token("a", "c1", TenantScope::Query);
        assert!(is_tenant_token(&q));
        assert_eq!(key.bearer_scope(&q, "a", "c1"), Some(TenantScope::Query));
        assert_eq!(key.bearer_scope(&q, "b", "c1"), None, "another tenant");
        assert_eq!(key.bearer_scope(&q, "a", "c2"), None, "another cell");
        let d = key.token("a", "c1", TenantScope::Detect);
        assert_eq!(key.bearer_scope(&d, "a", "c1"), Some(TenantScope::Detect));
        // The job key is never a bearer.
        let j = key.token("a", "c1", TenantScope::Job);
        assert_eq!(key.bearer_scope(&j, "a", "c1"), None);
        // Another full token derives other tokens.
        let other = TenantKey::from_router_token("another-full-router-token-0123456789abcdef");
        assert_eq!(other.bearer_scope(&q, "a", "c1"), None);
        // Separator: ("ab","c") and ("a","bc") differ.
        assert_ne!(key.token("ab", "c", TenantScope::Query).as_str(), key.token("a", "bc", TenantScope::Query).as_str());
    }

    #[test]
    fn job_spec_signatures_bind_body_tenant_and_cell() {
        let key = TenantKey::from_router_token(GOLDEN_FULL);
        let job = key.token("a", "c1", TenantScope::Job);
        let sig = sign_job_spec(&job, "a", "c1", b"{\"x\":1}");
        assert!(key.verify_job_spec("a", "c1", b"{\"x\":1}", &sig));
        assert!(!key.verify_job_spec("a", "c1", b"{\"x\":2}", &sig), "body edited");
        assert!(!key.verify_job_spec("b", "c1", b"{\"x\":1}", &sig), "another tenant");
        assert!(!key.verify_job_spec("a", "c2", b"{\"x\":1}", &sig), "another cell");
        // A query bearer cannot sign.
        let q = key.token("a", "c1", TenantScope::Query);
        assert!(!key.verify_job_spec("a", "c1", b"{\"x\":1}", &sign_job_spec(&q, "a", "c1", b"{\"x\":1}")));
        assert!(TenantKey::from_hex("zz").is_err());
        assert!(TenantKey::from_hex(&"ab".repeat(31)).is_err());
    }
}
