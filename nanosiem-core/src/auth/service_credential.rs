// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private service listeners and the shared service credential (NAN-2042).
//!
//! Operational routes that are not part of the user-facing API — Prometheus
//! `/metrics` on api, search and jobs, and the jobs health listener — used to
//! be reachable by anything on the pod / container network: jobs bound
//! `0.0.0.0` with no auth, and `/metrics` was open whenever
//! `METRICS_AUTH_TOKEN` happened to be unset.
//!
//! The single-tenant model is deliberately minimal (the hosted route-capability
//! registry from `main` is not carried):
//!
//! * **One shared service credential.** `NANO_SERVICE_TOKEN`, falling back to
//!   the pre-existing `METRICS_AUTH_TOKEN` so current Prometheus scrape configs
//!   keep working. Presented as `Authorization: Bearer <token>` and compared in
//!   constant time.
//! * **Fail closed.** With a credential configured, every caller must present
//!   it. On the USER-FACING api/search listeners the credential is always
//!   required ([`LoopbackPolicy::RequireToken`]): a same-host reverse proxy
//!   makes every proxied request arrive from loopback, so the TCP peer is no
//!   proof of anything there. Tokenless loopback access
//!   ([`LoopbackPolicy::AllowWhenUnconfigured`]) is reserved for the jobs
//!   listener, which is itself bound to loopback and never proxied.
//! * **Private bind.** The jobs listener binds loopback unless the operator
//!   opts into a wider address with `JOBS_BIND_ADDR`.
//!
//! This module is the pure decision core; the axum wrappers live in each
//! service so `nanosiem-core` stays framework-free.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Env var naming the shared service credential.
pub const SERVICE_TOKEN_ENV: &str = "NANO_SERVICE_TOKEN";
/// Legacy metrics-only credential, honored as a fallback.
pub const LEGACY_METRICS_TOKEN_ENV: &str = "METRICS_AUTH_TOKEN";
/// Env var that widens the jobs listener bind address (default loopback).
pub const JOBS_BIND_ADDR_ENV: &str = "JOBS_BIND_ADDR";

/// Outcome of a private-route admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAdmission {
    /// Caller presented the configured credential.
    Credential,
    /// No credential is configured and the caller is a loopback peer.
    Loopback,
    /// Refused: respond 401 without detail.
    Denied,
}

impl ServiceAdmission {
    pub fn is_allowed(self) -> bool {
        !matches!(self, ServiceAdmission::Denied)
    }
}

/// Whether a loopback peer may skip the credential when none is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackPolicy {
    /// api / search `/metrics`: the token is always required.
    RequireToken,
    /// jobs' loopback-only listener: with no token configured a loopback peer
    /// is admitted (in-container health/metrics probes).
    AllowWhenUnconfigured,
}

/// The configured shared service credential, if any.
#[derive(Clone, Default)]
pub struct ServiceCredential {
    token: Option<String>,
}

impl std::fmt::Debug for ServiceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceCredential")
            .field("configured", &self.token.is_some())
            .finish()
    }
}

impl ServiceCredential {
    /// Build from explicit values; empty / whitespace-only values are unset.
    pub fn new(primary: Option<String>, legacy: Option<String>) -> Self {
        let clean = |v: Option<String>| v.filter(|t| !t.trim().is_empty());
        Self {
            token: clean(primary).or_else(|| clean(legacy)),
        }
    }

    /// `NANO_SERVICE_TOKEN`, else `METRICS_AUTH_TOKEN`.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var(SERVICE_TOKEN_ENV).ok(),
            std::env::var(LEGACY_METRICS_TOKEN_ENV).ok(),
        )
    }

    pub fn is_configured(&self) -> bool {
        self.token.is_some()
    }

    /// Decide whether a request may reach a private route.
    ///
    /// `authorization` is the raw `Authorization` header value (exactly one;
    /// callers must pass `None` when the header is absent, repeated or not
    /// valid UTF-8). `peer` is the TCP peer address — never a forwarded-for
    /// header, which any client can forge.
    pub fn admit(
        &self,
        authorization: Option<&str>,
        peer: Option<IpAddr>,
        loopback: LoopbackPolicy,
    ) -> ServiceAdmission {
        match &self.token {
            Some(expected) => {
                let presented = authorization.and_then(|v| v.strip_prefix("Bearer "));
                match presented {
                    Some(p) if constant_time_eq(p.as_bytes(), expected.as_bytes()) => {
                        ServiceAdmission::Credential
                    }
                    _ => ServiceAdmission::Denied,
                }
            }
            None if loopback == LoopbackPolicy::AllowWhenUnconfigured
                && peer.is_some_and(is_loopback) =>
            {
                ServiceAdmission::Loopback
            }
            None => ServiceAdmission::Denied,
        }
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        // `::ffff:127.0.0.1` from a dual-stack socket is still loopback.
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Resolve the jobs listener address. Loopback by default; an operator who
/// needs the listener on the pod network (e.g. a Prometheus scrape) sets
/// `JOBS_BIND_ADDR=0.0.0.0` and a service credential. An unparsable value is
/// refused rather than silently widened.
pub fn private_bind_addr(configured: Option<&str>, port: u16) -> Result<SocketAddr, String> {
    match configured.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        Some(raw) => raw
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, port))
            .map_err(|_| format!("{JOBS_BIND_ADDR_ENV} must be an IP address, got {raw:?}")),
    }
}
