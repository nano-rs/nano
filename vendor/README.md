# Vendored crates

`[patch.crates-io]` in the workspace `Cargo.toml` points at these.

- `sqlx-core` 0.8.6 (crates.io, MIT OR Apache-2.0), unmodified except
  `src/net/socket/mod.rs::connect_tcp`: opt-in client TCP keepalive via
  `NANO_SQLX_TCP_KEEPALIVE_SECS` (NAN-4949, ported by NAN-4955), plus the
  `socket2` dependency it needs. With the variable unset (every service but
  the platform feed publisher) behaviour is identical to upstream.
