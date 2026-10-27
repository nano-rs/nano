// SPDX-License-Identifier: AGPL-3.0-or-later
fn main() {
    if let Err(e) = nanosiem_lake_cell::worker_launch::run_worker_launcher() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
