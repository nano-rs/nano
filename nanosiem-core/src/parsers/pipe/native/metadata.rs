// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed metadata envelope around reduce. Only this exact, guarded subgraph
//! may restore platform-owned metadata; tenant remaps remain read-only.
use super::*;

pub const STASH: &str = include_str!("stash.vrl");
pub const RESTORE: &str = include_str!("restore.vrl");

pub(super) fn stash_transform(inputs: Vec<String>) -> toml::Table {
    remap(STASH.into(), inputs)
}
pub(super) fn restore_transform(inputs: Vec<String>) -> toml::Table {
    remap(RESTORE.into(), inputs)
}

/// Recognise the source AND its complete trusted data path. Matching a name
/// or source alone would let an attacker feed a forged envelope to restore.
pub fn trusted_restore(prefix: &str, name: &str, transforms: &toml::Table) -> bool {
    let Some(index) = name
        .strip_prefix(&format!("{prefix}_pipe_"))
        .and_then(|tail| tail.strip_suffix("_restore"))
        .and_then(|index| index.parse::<usize>().ok())
        .filter(|index| *index < 50)
    else {
        return false;
    };
    let id = |suffix| format!("{prefix}_pipe_{index}_{suffix}");
    if name != id("restore") {
        return false;
    }
    let body = |suffix| transforms.get(&id(suffix)).and_then(toml::Value::as_table);
    if body("restore") != Some(&restore_transform(vec![id("native")]))
        || body("stash") != Some(&stash_transform(vec![id("prepare")]))
        || body("control")
            != Some(&remap(
                ". = { \"group_hash\": .group_hash }".into(),
                vec![id("stash")],
            ))
    {
        return false;
    }
    let Some(reduce) = body("native") else {
        return false;
    };
    if reduce.get("type").and_then(toml::Value::as_str) != Some("reduce")
        || reduce.get("inputs") != Some(&strings(&[id("stash"), id("bound")]))
        || guard_transform("reduce", reduce).is_err()
    {
        return false;
    }
    let Some(merges) = reduce
        .get("merge_strategies")
        .and_then(toml::Value::as_table)
    else {
        return false;
    };
    for (field, strategy) in [
        ("_nano_pipe_metadata", "discard"),
        ("_nano_pipe_keys", "array"),
        ("context", "retain"),
        ("count", "sum"),
        ("group_hash", "retain"),
    ] {
        if merges.get(field).and_then(toml::Value::as_str) != Some(strategy) {
            return false;
        }
    }
    // No nested-path merge may override the trusted envelope's first value.
    if merges.keys().any(|field| {
        ![
            "_nano_pipe_metadata",
            "_nano_pipe_keys",
            "context",
            "count",
            "group_hash",
        ]
        .contains(&field.as_str())
            && !field
                .strip_prefix("value_")
                .is_some_and(|index| index.parse::<usize>().is_ok_and(|index| index < 16))
    }) {
        return false;
    }
    let Some(bound) = body("bound") else {
        return false;
    };
    let Some(timeout) = reduce
        .get("expire_after_ms")
        .and_then(toml::Value::as_integer)
    else {
        return false;
    };
    bound == &bound_transform((timeout / 1000) as u64, vec![id("control")])
}
