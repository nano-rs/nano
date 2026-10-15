# Local patch: dotted child names in `unmapped`

Source: crates.io iceberg 0.10.1 (the registry source pinned in Cargo.lock before this patch). Registry-only metadata files (`Cargo.lock`, `.cargo_vcs_info.json`, `.cargo-ok`, `public-api.txt`, `DEPENDENCIES.rust.tsv`) were dropped, and `[dev-dependencies]` were removed from `Cargo.toml` so the vendored crate adds nothing to the workspace lockfile (its own unit tests are not run here; `nanosiem-lake-worker` carries the regression test).

Apart from that manifest trim, only `src/transaction/update_schema.rs` differs. `UpdateSchemaAction` refused every added field whose name contains `.`, even when the field is added under an explicit parent. The patch keeps that refusal for root-level additions, where `a.b` really is ambiguous, and allows it under a parent, which matches Java's `UpdateSchema.addColumn(parent, name, type)`. A full-name collision (`unmapped.a.b` existing both as a nested leaf and as a flat dotted child) is still refused when the new `Schema` is built.

Why this is needed: the ocsf-1.9 catalog parsers' residual spill writes flat dotted keys under the free-form OCSF `unmapped` object, for example `unmapped["event_data.destination_is_ipv_6"]`. The lean path keeps that literal child name in its Parquet `unmapped` struct. Without this patch the open-core Iceberg publisher could not add such a child to an existing `unmapped` struct, and it wedged the Bronze shard.

Remove this patch once upstream iceberg-rust accepts dotted names under an explicit parent.
