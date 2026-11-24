// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5849: a stored OCSF event never spells one ClickHouse `JSON` path twice.
//!
//! ClickHouse's `JSON` type joins the keys of nested objects with `.` into one
//! path and does not escape a `.` inside a key, so `{"a.b": 1}` and
//! `{"a": {"b": 1}}` are the same stored path `a.b`. A row whose object holds
//! two non-null values at one path (`{"a.b": 1, "a": {"b": 2}}`, or mixed
//! spellings such as `{"a": {"b.c": 1}, "a.b": {"c": 2}}`) is refused with
//! Code 117 (duplicate path). Vector's ClickHouse sink does not retry that
//! error, so one such event dropped its whole sink batch, co-batched events
//! from every other source included. Each object inside an array is its own
//! JSON document with the same rule.
//!
//! # The scheme (deterministic, lossless)
//!
//! Two values collide when their key paths read the same once the keys are
//! joined with `.`; then at least one of the keys on one of the paths holds a
//! `.`. In an event with a collision, every key whose head (the text before
//! its first `.`) is the head of a dotted key on a colliding path has its
//! dots escaped, RFC 6901 style: `~` becomes `~0` and `.` becomes `~1`. So
//! `{"a.b": 1, "a": {"b": 2}}` is stored as `a.b = 2` (the nested spelling,
//! unchanged) and `a~1b = 1`. Every key that holds a `~` is escaped too, so
//! the renaming cannot clash with a key that was already spelled `a~1b`. The
//! rule applies to every object of the event, the objects inside arrays
//! included. No value is changed or dropped, a key is only ever renamed in an
//! event that would otherwise collide, and only keys with a colliding head
//! are renamed; everything else is stored byte for byte as before. The
//! renamed keys are queryable in nPL (`unmapped.a~1b`).
//!
//! When an event has more than 64 colliding paths in one document, a key
//! holding a newline, or a dotted key in an array nested inside an array's
//! object (odd or hostile input), every dotted key in it is escaped instead,
//! which bounds the cost.
//!
//! # Where it runs, and what it costs
//!
//! Inline in every OCSF lane (each parser's `_ocsf_prepare` and
//! `generic_ocsf_prepare`), right after `nesting_depth_limit_vrl!`, so the
//! pipeline topology is unchanged: no component is added in front of the
//! disk-buffered `clickhouse_ocsf_logs` sink, and a hot reload never rewires
//! its inputs (rewiring during a reload can drop events already
//! acknowledged).
//!
//! 1. One regex over the text the depth limit already encoded
//!    (`nano_depth_json`): no dotted key anywhere, nothing else runs.
//! 2. Otherwise `flatten` by "\n" lists every value with its exact key path,
//!    and `flatten` by "." (what ClickHouse stores) is compared with it: the
//!    same count means no two values share a path. Only if one is shorter
//!    does a `tally` of the non-null paths read with "." find the colliding
//!    ones (a null stores nothing, so it never takes a path). Each object in
//!    an array holding a dotted key is checked the same way, the arrays read
//!    from the exact "\n" listing.
//! 3. Only on a collision are the colliding heads collected and the keys
//!    rewritten with one `map_keys`.
//!
//! The snippet is small (about 60 lines, a few closures), so it adds little
//! to each parser's compile time on a Vector reload (about 20 to 30 ms per
//! parser measured with `vector validate`, against about 170 ms for the
//! first, flatten-and-rebuild version).

/// See the module docs. `$var` names the VRL variable holding the event about
/// to be stored (only an object is changed). Runs right after
/// `nesting_depth_limit_vrl!` on the same variable: it reads that macro's
/// `nano_depth_json`.
macro_rules! json_path_collision_vrl {
    ($var:literal) => {
        concat!(
            r#"# NAN-5849: one stored JSON path is never spelled twice (flat dotted and
# nested); see json_path_collision.rs in vector_config.
nano_jp_has_dotted = match(nano_depth_json, r'\.(?:[^"\\]|\\.)*":')
nano_jp_maybe = false
if nano_jp_has_dotted && is_object("#, $var, r#") {
    nano_jp_all = false
    nano_jp_heads = "\n"
    if match(nano_depth_json, r'\\n(?:[^"\\]|\\.)*":') {
        # A key holding a newline: the "\n" join below is not exact.
        nano_jp_all = true
    } else {
        # Every non-null value with its exact key path ("\n" joins keys); a
        # null stores nothing, so it never takes a path.
        nano_jp_all_paths = flatten(object!("#, $var, r#"), "\n")
        nano_jp_docs = [{}]
        # Fast path: no two values share a "."-joined path, nulls included.
        if length(flatten(object!("#, $var, r#"), ".")) < length(nano_jp_all_paths) {
            nano_jp_docs = [filter(nano_jp_all_paths) -> |_nano_jp_k, nano_jp_x| { nano_jp_x != null }]
        }
        # Each object in an array is its own document.
        nano_jp_lists = filter(values(nano_jp_all_paths)) -> |_nano_jp_i, nano_jp_x| { is_array(nano_jp_x) }
        if length(nano_jp_lists) > 0 && match(encode_json(nano_jp_lists), r'\.(?:[^"\\]|\\.)*":') {
            nano_jp_inner = filter(flatten(nano_jp_lists)) -> |_nano_jp_i, nano_jp_x| { is_object(nano_jp_x) }
            nano_jp_docs = append(nano_jp_docs, map_values(nano_jp_inner) -> |nano_jp_o| {
                filter(flatten(object!(nano_jp_o), "\n")) -> |_nano_jp_k, nano_jp_x| { nano_jp_x != null }
            })
        }
        for_each(nano_jp_docs) -> |nano_jp_di, nano_jp_doc| {
            if !nano_jp_all {
                nano_jp_doc = object!(nano_jp_doc)
                # A dotted key in an array inside an array document: conservative.
                if nano_jp_di > 0 && match(encode_json(filter(values(nano_jp_doc)) -> |_nano_jp_k, nano_jp_x| { is_array(nano_jp_x) }), r'\.(?:[^"\\]|\\.)*":') {
                    nano_jp_all = true
                }
                # Two values collide when their key paths read the same with "." joins.
                nano_jp_paths = map_values(keys(nano_jp_doc)) -> |nano_jp_p| { replace(string!(nano_jp_p), "\n", ".") }
                nano_jp_dup = keys(filter(tally(nano_jp_paths)) -> |_nano_jp_p, nano_jp_n| { nano_jp_n != 1 })
                if length(nano_jp_dup) > 64 {
                    nano_jp_all = true
                } else if length(nano_jp_dup) > 0 {
                    nano_jp_dupset = join(map_values(nano_jp_dup) -> |nano_jp_p| { encode_json(nano_jp_p) }, "\n")
                    nano_jp_dupset = "\n" + nano_jp_dupset + "\n"
                    # The heads of the dotted keys on each colliding path.
                    for_each(keys(nano_jp_doc)) -> |_nano_jp_j, nano_jp_p| {
                        nano_jp_p = string!(nano_jp_p)
                        if contains(nano_jp_dupset, "\n" + encode_json(replace(nano_jp_p, "\n", ".")) + "\n") {
                            for_each(split(nano_jp_p, "\n")) -> |_nano_jp_s, nano_jp_seg| {
                                if contains(string!(nano_jp_seg), ".") {
                                    nano_jp_heads = nano_jp_heads + encode_json(string(get(split(string!(nano_jp_seg), ".", limit: 2), [0]) ?? "") ?? "") + "\n"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    nano_jp_maybe = nano_jp_all || nano_jp_heads != "\n"
    if nano_jp_maybe {
        "#, $var, r#" = map_keys(object!("#, $var, r#"), recursive: true) -> |nano_jp_k| {
            nano_jp_head = string(get(split(nano_jp_k, ".", limit: 2), [0]) ?? "") ?? ""
            if contains(nano_jp_k, "~") || (contains(nano_jp_k, ".") && (nano_jp_all || contains(nano_jp_heads, "\n" + encode_json(nano_jp_head) + "\n"))) {
                replace(replace(nano_jp_k, "~", "~0"), ".", "~1")
            } else { nano_jp_k }
        }
        log("Escaped the dots in an event's keys that spelled a stored JSON path twice", level: "warn", rate_limit_secs: 60)
    }
}
"#
        )
    };
}

#[cfg(test)]
pub(crate) const JSON_PATH_COLLISION_TEST_VRL: &str = json_path_collision_vrl!("nano_test_value");

/// The step as the OCSF lanes splice it (on their `ocsf_event`).
#[cfg(test)]
pub(crate) const JSON_PATH_COLLISION_OCSF_EVENT_VRL: &str = json_path_collision_vrl!("ocsf_event");
