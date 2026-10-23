//! Stamps written at ingest are read back as stored (NAN-2510, NAN-4168:
//! no read-time enrichment masks). Run ignored tests with
//! NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256 pointing to a
//! digest-verified chDB C ABI library.
#[allow(unused_imports)]
use chrono::Utc;
#[allow(unused_imports)]
use serde_json::{json, Value};
use nanosiem_lake_worker::native::NativeChdb;

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

#[cfg(all(feature = "enterprise", target_os = "linux"))]
#[path = "support/stamp_visibility.rs"]
mod stamp_visibility;
