# Vendored crates

`[patch.crates-io]` in the workspace `Cargo.toml` points at these.

- `sqlx-core` 0.9.0 (crates.io, MIT OR Apache-2.0), unmodified except
  `src/net/socket/mod.rs::connect_tcp` (tokio path):
  - opt-in client TCP keepalive via `NANO_SQLX_TCP_KEEPALIVE_SECS` (NAN-4949,
    ported by NAN-4955), plus the `socket2` dependency it needs. With the
    variable unset (every service but the platform feed publisher) behaviour
    is identical to upstream;
  - `TCP_NODELAY` is set again. sqlx 0.8.6 set it; 0.9.0 stopped, which would
    put every PG round trip behind Nagle (NAN-5412).

  The NAN-5214 `NotValidForNameContext` fix in
  `src/net/tls/tls_rustls.rs::NoHostnameTlsVerifier` is upstream as of 0.9.0
  and no longer a local change.
