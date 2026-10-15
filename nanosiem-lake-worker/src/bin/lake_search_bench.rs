// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standalone local benchmark, sharing the existing production part-query lab.
#[path = "lake_part_query_lab.rs"]
mod lab;

fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    anyhow::ensure!(
        matches!(
            args.get(1).map(String::as_str),
            Some("generate-local" | "search-local")
        ),
        "usage: lake_search_bench generate-local DATASET [1|24] [EPS] | search-local DATASET"
    );
    lab::main()
}
