//! Canonical Vector component naming (NAN-2196).
//!
//! Vector component IDs are derived from user-supplied names, and that mapping
//! is a **contract between three subsystems that never call each other**:
//!
//!   1. `source_configs::service` writes `[sources.<id>]` into generated TOML;
//!   2. `parsers::vector_config` writes transform/sink names the same way;
//!   3. `log_sources::repository::health` reads `vector.component_id` back off
//!      collector error events to attribute them to a log source.
//!
//! (3) only works if it derives the ID exactly as (1) wrote it. Before this
//! module, (1) and (2) each had their own private copy of the transformation —
//! byte-identical, but nothing held them that way, and adding a third copy for
//! (3) would have made a silent divergence a matter of time. A divergence here
//! is invisible: errors simply stop being attributed, and a broken source reads
//! as a quiet one, which is the exact failure NAN-2196 exists to fix.
//!
//! One definition, one place. Both original call sites now delegate here.

/// Convert a user-supplied name into a Vector-safe identifier.
///
/// Non-alphanumerics collapse to `_` and the result is lowercased. This is
/// deliberately lossy and NOT reversible — `My Source` and `my-source` both
/// become `my_source`. Callers needing a round trip must keep the original.
pub fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

/// The `vector.component_id` a generated pull-source carries in its internal
/// log events.
///
/// This is the join key from a collector error back to the log source that
/// produced it. It must stay in lockstep with the `[sources.…]` key emitted by
/// the source-config generator; `component_id_matches_generated_source_name` in
/// this module's tests pins that.
pub fn source_component_id(name: &str) -> String {
    format!("{}_source", safe_name(name))
}

#[cfg(test)]
mod tests;
