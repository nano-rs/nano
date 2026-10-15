//! The patched vendor crate is excluded from the workspace. Compile its helper
//! unit tests here so the lake-worker validation command exercises admission
//! and cancellation without requiring a second Cargo workspace/lockfile.
#[allow(dead_code)]
#[path = "../../vendor/iceberg-storage-opendal/src/manifest_fetch.rs"]
mod manifest_fetch;
