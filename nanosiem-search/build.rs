// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

fn main() {
    // Enterprise search validates the same private overlay before serving.
    // The directory does not exist in the stripped open-core mirror.
    if Path::new("../migrations/postgres-enterprise").is_dir() {
        println!("cargo:rerun-if-changed=../migrations/postgres-enterprise");
    }
}
