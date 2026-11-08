// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

fn main() {
    // The enterprise API and one-shot migrator both embed this overlay.
    // It is intentionally absent from the stripped open-core mirror.
    if Path::new("../migrations/postgres-enterprise").is_dir() {
        println!("cargo:rerun-if-changed=../migrations/postgres-enterprise");
    }
}
