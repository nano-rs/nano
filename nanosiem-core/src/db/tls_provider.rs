// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-wide rustls crypto provider (NAN-5214).
//!
//! The dependency graph enables both rustls providers (`aws-lc-rs` through
//! hyper-rustls / the ClickHouse client, `ring` through sqlx's `tls-rustls`).
//! rustls then cannot pick one on its own and PANICS the first time sqlx
//! negotiates TLS with PostgreSQL. A single-node install never hits this
//! (its PostgreSQL has no TLS, so `sslmode=prefer` falls back to plaintext);
//! PostgreSQL HA enables `ssl = on` and `sslmode=verify-ca`. Install
//! `aws-lc-rs`, the provider the rest of the workspace already uses, once per
//! process before any pool is built.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the aws-lc-rs provider as the process default. Idempotent; a
/// provider some other code installed first is left in place.
pub fn install_default_crypto_provider() {
    INSTALL.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Whether a process-level rustls provider is installed (for startup
/// assertions and the regression test in nanosiem-api).
pub fn crypto_provider_installed() -> bool {
    rustls::crypto::CryptoProvider::get_default().is_some()
}

#[cfg(test)]
mod tests {
    #[test]
    fn installs_a_process_default_provider() {
        super::install_default_crypto_provider();
        super::install_default_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
