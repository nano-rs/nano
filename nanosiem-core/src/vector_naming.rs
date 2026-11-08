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

/// One generated identifier claimed by more than one row (NAN-2305).
///
/// `safe_name` being lossy is fine as a *transformation*; it is not fine as a
/// *namespace*, and everything the deploy writes is keyed on its output — the
/// parser TOML filename, the `[transforms.<safe>_parse]` ids inside it, the
/// `source_router` route key, the `[sources.<safe>_source]` block of a
/// source-config. Two rows that collapse to one value conflict nowhere the
/// user can see: both tables' uniqueness is on the raw `name`, so both rows
/// are accepted, and only the config writers then fight over one path. The
/// last writer wins the file; worse, if one of the pair is *disabled*, the
/// active writer's disabled-branch DELETES the file the enabled one just
/// wrote (`vector_config::deploy::deploy_parsers`). Duplicate route keys in
/// one `[transforms.source_router.route]` table make `_router.toml` fail to
/// parse, which takes the whole ingest pipeline down rather than one source.
/// Nothing in that chain reports an error attributable to the real cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCollision {
    /// The generated value that more than one row collapses to.
    pub generated_id: String,
    /// Display names, sorted, so the rendered error is stable across runs.
    pub names: Vec<String>,
}

/// Find generated identifiers claimed by more than one distinct row.
///
/// `rows` yields `(row id, generated id, display name)`. Callers compute the
/// generated id because the rule is not uniform — parsers use `safe_name` of
/// the name, source configurations pin a type-derived stem for system
/// singletons (`SourceConfigService::config_safe_stem`).
///
/// Distinctness is keyed on the row id, not the name: a caller that assembles
/// its parser slice from concatenated lists must not have one source reported
/// as colliding with itself, which would fail a deploy that is perfectly fine.
pub fn find_identity_collisions(
    rows: impl IntoIterator<Item = (uuid::Uuid, String, String)>,
) -> Vec<IdentityCollision> {
    use std::collections::BTreeMap;

    // BTreeMap, not HashMap: the rendered error is compared in tests and read
    // by operators, so identifier order must not vary run to run.
    let mut claims: BTreeMap<String, Vec<(uuid::Uuid, String)>> = BTreeMap::new();
    for (id, generated_id, name) in rows {
        claims.entry(generated_id).or_default().push((id, name));
    }

    claims
        .into_iter()
        .filter_map(|(generated_id, mut holders)| {
            holders.sort();
            holders.dedup_by_key(|(id, _)| *id);
            if holders.len() < 2 {
                return None;
            }
            let mut names: Vec<String> = holders.into_iter().map(|(_, name)| name).collect();
            names.sort();
            Some(IdentityCollision {
                generated_id,
                names,
            })
        })
        .collect()
}

/// The display name of an existing row already holding `generated_id`.
///
/// `existing` yields `(generated id, display name)` and must already exclude
/// the row being renamed — otherwise every rename that keeps the same stem
/// (`My Source` → `My  Source`) would be rejected as conflicting with itself.
pub fn find_identity_holder(
    generated_id: &str,
    existing: impl IntoIterator<Item = (String, String)>,
) -> Option<String> {
    existing
        .into_iter()
        .find_map(|(id, name)| (id == generated_id).then_some(name))
}

/// Operator-facing rejection for a create or rename that would take an
/// identifier another row already holds.
///
/// Names the conflicting row and the generated value, because "that name is
/// taken" is actively misleading here: the two names LOOK different
/// (`My Source` vs `my-source`) and the operator has no way to see why they
/// collide without being shown what they both generate.
pub fn describe_identity_conflict(
    subject: &str,
    requested_name: &str,
    generated_id: &str,
    holder: &str,
) -> String {
    format!(
        "the name '{requested_name}' generates the Vector identifier '{generated_id}', \
         which the existing {subject} '{holder}' already uses. Generated identifiers \
         lowercase the name and replace every non-alphanumeric character with '_', so \
         these two names produce one config filename and one router route. Choose a \
         name that differs by more than case, spacing or punctuation."
    )
}

/// Whether `name` would take a generated identifier another row already holds,
/// and the operator-facing explanation if so.
///
/// Composes [`safe_name`], [`find_identity_holder`] and
/// [`describe_identity_conflict`] so every caller applies the same rule. Pure,
/// so the decision is testable without a database: the caller supplies the
/// existing `(id, display name)` rows and the id to exclude when renaming.
///
/// NAN-2311: shared because it was not. NAN-2305 put this logic behind
/// `ParserService`, while `POST /api/log-sources` goes through
/// `LogSourceService` — so the guard never ran on the path the API and UI use,
/// and the collision surfaced as `500 A database error occurred` from the
/// unique index instead of a message naming the conflicting source.
pub fn generated_identity_conflict<Id: PartialEq + Copy>(
    subject: &str,
    name: &str,
    existing: &[(Id, String)],
    exclude: Option<Id>,
) -> Option<String> {
    let generated = safe_name(name);
    let holder = find_identity_holder(
        &generated,
        existing
            .iter()
            .filter(|(id, _)| Some(*id) != exclude)
            .map(|(_, existing_name)| (safe_name(existing_name), existing_name.clone())),
    )?;
    Some(describe_identity_conflict(subject, name, &generated, &holder))
}

/// Operator-facing deploy refusal when a whole staged/deployed set contains a
/// collision.
///
/// Resolving it is a rename, which only the operator can choose — picking one
/// automatically would silently stop ingesting the other source.
pub fn describe_identity_collisions(subject: &str, collisions: &[IdentityCollision]) -> String {
    let mut out = format!(
        "refusing to deploy: more than one {subject} generates the same Vector identifier. \
         That value is both the generated config filename and the router route key, so \
         deploying would overwrite one {subject}'s config with another's and silently stop \
         ingesting it. Rename all but one of the {subject}s listed for each identifier."
    );
    for collision in collisions {
        out.push_str(&format!(
            "\n  identifier '{}' is generated by: {}",
            collision.generated_id,
            collision.names.join(", "),
        ));
    }
    out
}

#[cfg(test)]
mod tests;
