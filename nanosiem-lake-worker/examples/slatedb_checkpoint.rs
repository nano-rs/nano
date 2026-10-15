// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inspect or create an exact checkpoint for a trusted local SlateDB snapshot.

use anyhow::{Context, Result, bail};
use slatedb::admin::AdminBuilder;
use slatedb::config::CheckpointOptions;
use slatedb::object_store::ObjectStore;
use slatedb::object_store::local::LocalFileSystem;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let database_path = arguments.next().context("database path is required")?;
    let create = arguments.next().as_deref() == Some("--create");
    if arguments.next().is_some() {
        bail!("usage: slatedb_checkpoint <relative-database-path> [--create]");
    }
    let object_store: Arc<dyn ObjectStore> = Arc::new(
        LocalFileSystem::new_with_prefix("/")
            .context("failed to open local object-store root")?,
    );
    let admin = AdminBuilder::new(database_path, object_store).build();
    if create {
        let checkpoint = admin
            .create_detached_checkpoint(&CheckpointOptions {
                lifetime: None,
                source: None,
                name: Some("nano-immutable-publication".to_string()),
            })
            .await?;
        println!(
            "{}",
            serde_json::json!({
                "created": true,
                "checkpoint_id": checkpoint.id,
                "manifest_id": checkpoint.manifest_id,
            })
        );
    } else {
        let checkpoints = admin.list_checkpoints(None).await?;
        let rows = checkpoints
            .into_iter()
            .map(|checkpoint| {
                serde_json::json!({
                    "checkpoint_id": checkpoint.id,
                    "manifest_id": checkpoint.manifest_id,
                    "name": checkpoint.name,
                    "expires": checkpoint.expire_time,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string(&rows)?);
    }
    Ok(())
}
