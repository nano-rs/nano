//! NAN-5723: cancel must kill every companion query a search can spawn, and
//! no two valid request ids may share a derived query id.

use super::{
    all_query_ids, companion_query_ids, validate_client_request_id, CompanionQuery,
    RequestIdError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const THIS_MODULE: &str = "nanosiem-core/src/search/companion_query_id.rs";

/// Workspace crates whose production sources are scanned (when present: the
/// open-core mirror has no enterprise crate).
const SCANNED_CRATES: &[&str] = &[
    "nanosiem-core",
    "nanosiem-search",
    "nanosiem-api",
    "nanosiem-api-lib",
    "nanosiem-enterprise",
];

/// Under this prefix every `format!("{…}-` / `format!("{}-` literal is a
/// companion id unless listed in `NOT_COMPANION_IDS`. Elsewhere only literals
/// whose argument names a query/request id are.
const SEARCH_DIR: &str = "nanosiem-core/src/search/";

/// Search-module `format!` literals that start `"{…}-` but are NOT companion
/// query ids: (file, text after the separator, reason).
const NOT_COMPANION_IDS: &[(&str, &str, &str)] = &[
    (
        "nanosiem-core/src/search/background/repository.rs",
        "a{}",
        "the background job's per-attempt BASE query id; cancel expands it through all_query_ids",
    ),
    (
        "nanosiem-core/src/search/service/lateral_graph.rs",
        "other",
        "an auth-method label, not a query id",
    ),
];

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A test-only file by name (`*_tests.rs`, `tests.rs`, `*_test.rs`,
/// `test_support.rs`): its construction sites prove nothing about production.
fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with("tests.rs") || name.ends_with("_test.rs") || name.starts_with("test_support")
}

/// One masked view of a Rust source, byte-aligned with the original.
struct Masked {
    /// Comments blanked to spaces; string and char literals kept.
    code: String,
    /// Comments AND literal contents blanked (for brace matching).
    shape: String,
}

/// Blank comments (and, in `shape`, literal contents) without moving bytes.
fn mask(src: &str) -> Masked {
    let b = src.as_bytes();
    let mut code = b.to_vec();
    let mut shape = b.to_vec();
    let blank = |v: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut v[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
            blank(&mut code, i, end);
            blank(&mut shape, i, end);
            i = end;
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            let mut j = i;
            while j < b.len() {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            blank(&mut shape, i, j);
            i = j;
        } else if b[i] == b'r' && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            let open = i + 1 + hashes;
            if b.get(open) != Some(&b'"') {
                i += 1;
                continue;
            }
            let closer: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
            let body = open + 1;
            let end = src[body..]
                .as_bytes()
                .windows(closer.len())
                .position(|w| w == closer.as_slice())
                .map_or(b.len(), |p| body + p);
            blank(&mut shape, body, end);
            i = (end + closer.len()).min(b.len());
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            blank(&mut shape, i + 1, j.min(b.len()));
            i = j + 1;
        } else if b[i] == b'\'' {
            // A char literal ('x', '\n', '\''), not a lifetime ('a).
            let end = if b.get(i + 1) == Some(&b'\\') {
                src[i + 3..].find('\'').map(|p| i + 3 + p)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                // Multi-byte char literal, else a lifetime.
                src[i + 1..].chars().next().and_then(|c| {
                    let after = i + 1 + c.len_utf8();
                    (b.get(after) == Some(&b'\'')).then_some(after)
                })
            };
            match end {
                Some(end) => {
                    blank(&mut shape, i + 1, end);
                    i = end + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    Masked {
        code: String::from_utf8(code).expect("utf8"),
        shape: String::from_utf8(shape).expect("utf8"),
    }
}

/// Byte ranges of `#[cfg(test)]` items (`mod x { … }` or one fn/impl body).
fn cfg_test_ranges(shape: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for (start, _) in shape.match_indices("#[cfg(test)]") {
        let rest = &shape[start..];
        // A file module (`mod x;`) ends at the semicolon; its file is a test
        // file by name or excluded via its own cfg(test) contents.
        let brace = rest.find('{');
        let semi = rest.find(';');
        let Some(brace) = brace.filter(|b| semi.is_none_or(|s| *b < s)) else {
            continue;
        };
        let mut depth = 0usize;
        let mut end = shape.len();
        for (i, c) in rest[brace..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + brace + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        ranges.push((start, end));
    }
    ranges
}

/// (workspace-relative path, production code with comments and test items
/// blanked) for every non-test Rust source in the scanned crates.
fn production_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    for krate in SCANNED_CRATES {
        rust_sources(&root.join(krate).join("src"), &mut files);
    }
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under workspace")
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let masked = mask(&src);
        let mut code = masked.code.into_bytes();
        for (from, to) in cfg_test_ranges(&masked.shape) {
            for c in &mut code[from..to] {
                if *c != b'\n' {
                    *c = b' ';
                }
            }
        }
        out.push((rel, String::from_utf8(code).expect("utf8")));
    }
    assert!(
        out.iter().any(|(rel, _)| rel.starts_with(SEARCH_DIR)),
        "scan found no search sources: is the workspace layout different?"
    );
    out
}

/// One `format!` call: the literal's text and the argument text after it.
struct FormatCall<'a> {
    offset: usize,
    literal: &'a str,
    args: &'a str,
}

/// Every `format!` call with a plain string literal first, whitespace and
/// line breaks allowed anywhere rustfmt puts them.
fn format_calls(code: &str) -> Vec<FormatCall<'_>> {
    let mut out = Vec::new();
    for (i, _) in code.match_indices("format!") {
        let rest = code[i + "format!".len()..].trim_start();
        let Some(rest) = rest.strip_prefix('(') else { continue };
        let rest = rest.trim_start();
        let Some(body) = rest.strip_prefix('"') else { continue };
        let bytes = body.as_bytes();
        let mut j = 0;
        while j < bytes.len() && bytes[j] != b'"' {
            j += if bytes[j] == b'\\' { 2 } else { 1 };
        }
        let literal = &body[..j.min(body.len())];
        let after = &body[(j + 1).min(body.len())..];
        let mut depth = 0i32;
        let mut end = after.len();
        for (k, c) in after.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => {
                    end = k;
                    break;
                }
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        out.push(FormatCall {
            offset: i,
            literal,
            args: &after[..end],
        });
    }
    out
}

fn is_id_like(text: &str) -> bool {
    text.contains("query_id") || text.contains("request_id") || text.contains("qid")
}

/// A literal that derives an id from a leading placeholder: `{x}-…`, `{}-…`,
/// `{x}_…` or `{}_…`. Returns (placeholder name, separator, text after it).
fn derived_id_shape(literal: &str) -> Option<(&str, char, &str)> {
    let inner = literal.strip_prefix('{')?;
    let close = inner.find('}')?;
    let name = &inner[..close];
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
        return None;
    }
    let after = &inner[close + 1..];
    let sep = after.chars().next().filter(|c| matches!(c, '-' | '_'))?;
    Some((name, sep, &after[1..]))
}

/// Variant names declared in `enum CompanionQuery { … }`, parsed from the
/// comment-stripped source so inline comments and a missing trailing comma
/// cannot hide one.
fn declared_variants() -> Vec<String> {
    let src = std::fs::read_to_string(workspace_root().join(THIS_MODULE)).expect("read module");
    let code = mask(&src).code;
    let start = code
        .find("enum CompanionQuery {")
        .expect("enum declaration");
    let body = &code[start + "enum CompanionQuery {".len()..];
    let body = &body[..body.find('}').expect("enum end")];
    body.split(',')
        .map(|item| {
            // Drop attributes such as `#[doc = …]` on the item.
            let item = item.trim();
            let item = item.rsplit(']').next().unwrap_or(item).trim();
            item.to_string()
        })
        .filter(|item| !item.is_empty())
        .inspect(|item| {
            assert!(
                item.chars().all(|c| c.is_ascii_alphanumeric()),
                "unexpected variant shape `{item}`: only unit variants are supported"
            );
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Kill-set shape
// ---------------------------------------------------------------------------

#[test]
fn all_lists_every_variant() {
    let declared: BTreeSet<String> = declared_variants().into_iter().collect();
    let listed: BTreeSet<String> = CompanionQuery::ALL.iter().map(|c| format!("{c:?}")).collect();
    assert!(declared.len() >= 9, "parsed too few variants: {declared:?}");
    assert_eq!(listed.len(), CompanionQuery::ALL.len(), "ALL lists a variant twice");
    assert_eq!(
        declared, listed,
        "CompanionQuery::ALL must list every variant: cancel builds its kill set from it"
    );
    let suffixes: BTreeSet<&str> = CompanionQuery::ALL.iter().map(|c| c.suffix()).collect();
    assert_eq!(suffixes.len(), CompanionQuery::ALL.len(), "two companions share a suffix");
}

/// NAN-1428: the id scheme is fixed. Cancel derives these exact ids; changing
/// a suffix breaks kill coverage for searches in flight during a rolling
/// deploy. NAN-5723 added the rest after `-prevalence-rescue`.
#[test]
fn companion_ids_are_exact_derived_suffixes() {
    assert_eq!(
        companion_query_ids("req-1"),
        [
            "req-1-count",
            "req-1-hist",
            "req-1-fstats",
            "req-1-aggregate-count",
            "req-1-inv-spill",
            "req-1-inv-extended",
            "req-1-guard",
            "req-1-prevalence-rescue",
            "req-1-base-count",
            "req-1-chunk-0",
            "req-1-chunk-1",
            "req-1-rescue-probe-hash",
            "req-1-rescue-probe-domain",
            "req-1-rescue-probe-ip",
            "req-1-prevalence-recheck",
        ]
    );
    let all = all_query_ids("req-1");
    assert_eq!(all[0], "req-1");
    assert_eq!(all[1..], companion_query_ids("req-1")[..]);
    // Ids with LIKE metacharacters stay literal: derivation is plain
    // concatenation, matching is exact (never LIKE).
    assert_eq!(all_query_ids("a%b_c")[1], "a%b_c-count");
}

/// The NAN-5723 regression: the prevalence pushdown's base count, the
/// streaming chunks and the prevalence probes were not in the kill set.
#[test]
fn kill_set_includes_every_formerly_missed_companion() {
    let kill = all_query_ids("Q");
    for id in [
        "Q-base-count",
        "Q-chunk-0",
        "Q-chunk-1",
        "Q-rescue-probe-hash",
        "Q-rescue-probe-domain",
        "Q-rescue-probe-ip",
        "Q-prevalence-recheck",
    ] {
        assert!(kill.contains(&id.to_string()), "{id} missing");
    }
}

/// Streaming chunks alternate, so consecutive chunks never share an id and
/// every chunk index maps into the kill set.
#[test]
fn stream_chunks_alternate_inside_the_kill_set() {
    let kill = all_query_ids("Q");
    for i in 0..400 {
        let id = CompanionQuery::stream_chunk(i).query_id("Q");
        assert!(kill.contains(&id), "chunk {i} ({id}) not killable");
        assert_ne!(id, CompanionQuery::stream_chunk(i + 1).query_id("Q"));
    }
}

// ---------------------------------------------------------------------------
// Construction-site coverage
// ---------------------------------------------------------------------------

/// Enumerate every derived-id construction site in production code (comments,
/// test files and `#[cfg(test)]` items excluded) and require the kill set to
/// cover it:
///
/// 1. Every `CompanionQuery::<Variant>` use names a variant whose id is in
///    `all_query_ids`, and every variant is used somewhere (an unused
///    companion is dead weight in every KILL).
/// 2. No derived id is built by hand. Under `nanosiem-core/src/search` any
///    `format!` whose literal starts `{…}-` (inline or positional) is a
///    companion id unless allowlisted; in every scanned crate, one starting
///    `{…}-` or `{…}_` whose placeholder or first argument names a
///    query/request id is. Build it
///    from a `CompanionQuery` variant instead so cancel kills it.
#[test]
fn kill_set_covers_every_derived_companion_query_id() {
    let kill_set: BTreeSet<String> = all_query_ids("Q").into_iter().collect();
    let by_name: BTreeMap<String, CompanionQuery> =
        CompanionQuery::ALL.iter().map(|c| (format!("{c:?}"), *c)).collect();

    let mut constructed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut hand_built = Vec::new();
    let mut allowlist_hits = BTreeSet::new();
    // `stream_chunk(i)` is a construction of both chunk variants.
    const CHUNK_SITE: &str = "CompanionQuery::stream_chunk(";

    for (rel, code) in production_sources() {
        if rel == THIS_MODULE {
            continue;
        }

        // 1. Enum construction sites.
        const SITE: &str = "CompanionQuery::";
        for (i, _) in code.match_indices(SITE) {
            if code[i..].starts_with(CHUNK_SITE) {
                for v in [CompanionQuery::StreamChunkEven, CompanionQuery::StreamChunkOdd] {
                    constructed.entry(format!("{v:?}")).or_default().push(rel.clone());
                }
                continue;
            }
            let name: String = code[i + SITE.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if name == "ALL" {
                continue;
            }
            let variant = by_name
                .get(&name)
                .unwrap_or_else(|| panic!("{rel}: unknown CompanionQuery::{name}"));
            assert!(
                kill_set.contains(&variant.query_id("Q")),
                "{rel}: CompanionQuery::{name} id is not in all_query_ids"
            );
            constructed.entry(name).or_default().push(rel.clone());
        }

        // 2. Hand-built derived ids.
        let in_search = rel.starts_with(SEARCH_DIR);
        for call in format_calls(&code) {
            let Some((placeholder, sep, tail)) = derived_id_shape(call.literal) else {
                continue;
            };
            let first_arg = call
                .args
                .trim_start()
                .strip_prefix(',')
                .unwrap_or("")
                .split(',')
                .next()
                .unwrap_or("");
            let id_like = if placeholder.is_empty() {
                is_id_like(first_arg)
            } else {
                is_id_like(placeholder)
            };
            // `_` under search is mostly column naming (`{p}_host_count`);
            // it only counts when the placeholder/argument is an id.
            if !(id_like || (in_search && sep == '-')) {
                continue;
            }
            if let Some((file, prefix, _)) = NOT_COMPANION_IDS
                .iter()
                .find(|(file, prefix, _)| *file == rel && tail.starts_with(prefix))
            {
                allowlist_hits.insert((*file, *prefix));
                continue;
            }
            let line = code[..call.offset].lines().count();
            hand_built.push(format!("{rel}:{line}: format!(\"{}\" …)", call.literal));
        }
    }

    assert!(
        hand_built.is_empty(),
        "derived query ids built by hand (build them from a CompanionQuery variant so cancel kills them):\n{}",
        hand_built.join("\n")
    );
    let unused: Vec<&String> = by_name.keys().filter(|n| !constructed.contains_key(*n)).collect();
    assert!(
        unused.is_empty(),
        "companions in the kill set that no production code constructs: {unused:?}"
    );
    // A stale allowlist entry could later mask a real companion: keep it exact.
    for (file, prefix, _) in NOT_COMPANION_IDS {
        assert!(
            allowlist_hits.contains(&(*file, *prefix)),
            "NOT_COMPANION_IDS entry ({file}, {prefix}) matched nothing; remove it"
        );
    }
}

/// The scanner's own blind spots, pinned: multi-line and positional
/// `format!`, `_` separators, comments and `#[cfg(test)]` items.
#[test]
fn scanner_sees_through_formatting_and_ignores_comments_and_tests() {
    let src = r#"
fn a(query_id: &str) -> String {
    format!(
        "{query_id}-sneaky",
    )
}
fn b(query_id: &str) -> String { format!("{}_other", query_id) }
// format!("{query_id}-in-a-comment")
/* format!("{query_id}-in-a-block") */
fn c() -> &'static str { "format!(\"{query_id}-in-a-string\")" }
#[cfg(test)]
mod tests {
    fn d(query_id: &str) -> String { format!("{query_id}-in-a-test") }
}
"#;
    let masked = mask(src);
    let mut code = masked.code.into_bytes();
    for (from, to) in cfg_test_ranges(&masked.shape) {
        for ch in &mut code[from..to] {
            if *ch != b'\n' {
                *ch = b' ';
            }
        }
    }
    let code = String::from_utf8(code).unwrap();
    let found: Vec<(String, String)> = format_calls(&code)
        .into_iter()
        .filter_map(|c| derived_id_shape(c.literal).map(|(p, _, t)| (p.to_string(), t.to_string())))
        .collect();
    assert_eq!(
        found,
        vec![
            ("query_id".to_string(), "sneaky".to_string()),
            (String::new(), "other".to_string()),
        ],
        "only the two real calls are seen; comments, the string literal and the cfg(test) mod are not"
    );

    // An inline comment or a missing trailing comma cannot hide a variant.
    let enum_src = "enum CompanionQuery {\n    A, // note\n    /// doc\n    B\n}";
    let code = mask(enum_src).code;
    let body = &code[code.find('{').unwrap() + 1..code.find('}').unwrap()];
    let names: Vec<&str> = body.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    assert_eq!(names, ["A", "B"]);
}

// ---------------------------------------------------------------------------
// Client request-id validation (cross-principal KILL, NAN-5723)
// ---------------------------------------------------------------------------

#[test]
fn request_ids_used_by_real_clients_are_accepted() {
    for id in [
        "0195f0c2-8a7d-7b3e-9c1a-1234567890ab",
        "019a3b2c-0000-7000-8000-a12345678901",
        "soar-search:0195f0c2-8a7d-7b3e-9c1a-1234567890ab",
        "my_search.1",
        "count",
        "hist",
        "a-countdown",
        "basecount",
    ] {
        assert_eq!(validate_client_request_id(id), Ok(()), "{id}");
    }
}

#[test]
fn request_ids_that_could_collide_are_refused() {
    for id in [
        "job-count",
        "job-base-count",
        "job-COUNT",
        "job-chunk-0",
        "job-chunk-1",
        "job-prevalence-rescue",
        "job-rescue-probe-ip",
        // Hyphen prefixes of a two-part suffix: `job-base` + `-count` is
        // `job` + `-base-count`.
        "job-base",
        "job-aggregate",
        "job-inv",
        "job-prevalence",
        "job-rescue",
        "job-rescue-probe",
        "job-chunk",
    ] {
        assert_eq!(validate_client_request_id(id), Err(RequestIdError::ReservedSuffix), "{id}");
    }
    assert_eq!(validate_client_request_id(""), Err(RequestIdError::Length));
    assert_eq!(validate_client_request_id(&"a".repeat(129)), Err(RequestIdError::Length));
    for id in ["a b", "a%b", "a'b", "a/b", "ä"] {
        assert_eq!(validate_client_request_id(id), Err(RequestIdError::Charset), "{id}");
    }
}

/// The security property behind the validation: cancel authorizes on the raw
/// id (one owner per id) and kills `all_query_ids(id)`. If no two distinct
/// valid ids share a derived id, a principal can only ever kill its own
/// queries. Brute-force every id built from a base plus any chain of suffix
/// pieces.
#[test]
fn distinct_valid_request_ids_never_share_a_derived_query_id() {
    let mut pieces: BTreeSet<String> = BTreeSet::new();
    for c in CompanionQuery::ALL {
        let suffix = c.suffix();
        pieces.insert(suffix.to_string());
        for (i, _) in suffix.match_indices('-') {
            pieces.insert(suffix[..i].to_string());
            pieces.insert(suffix[i + 1..].to_string());
        }
    }
    let pieces: Vec<String> = pieces.into_iter().collect();
    let mut ids: BTreeSet<String> = ["job", "a"].iter().map(|s| s.to_string()).collect();
    for _ in 0..2 {
        let next: Vec<String> = ids
            .iter()
            .flat_map(|id| pieces.iter().map(move |p| format!("{id}-{p}")))
            .collect();
        ids.extend(next);
    }
    let valid: Vec<&String> = ids.iter().filter(|id| validate_client_request_id(id).is_ok()).collect();
    assert!(valid.len() > 10, "too few valid ids to be meaningful: {valid:?}");

    let mut owner_of: BTreeMap<String, &String> = BTreeMap::new();
    for id in &valid {
        for derived in all_query_ids(id) {
            if let Some(other) = owner_of.insert(derived.clone(), id) {
                panic!("`{other}` and `{id}` both own derived id `{derived}`: one could KILL the other's query");
            }
        }
    }

    // The attacks from the review, as concrete pairs.
    for (victim, attacker) in [("job-base-count", "job"), ("job", "job-base-count"), ("job-base", "job")] {
        let victim_ok = validate_client_request_id(victim).is_ok();
        let attacker_ok = validate_client_request_id(attacker).is_ok();
        let overlap = all_query_ids(victim).iter().any(|v| all_query_ids(attacker).contains(v));
        assert!(overlap, "the pair ({victim}, {attacker}) should collide without validation");
        assert!(!(victim_ok && attacker_ok), "validation must refuse one of ({victim}, {attacker})");
    }
}

/// One principal cannot take over another's request id (and so cannot
/// cancel it): the tracker refuses a second owner.
#[test]
fn another_principal_cannot_reserve_an_owned_request_id() {
    let tracker = crate::search::query_tracking::QueryTracker::new();
    let alice = uuid::Uuid::now_v7();
    let bob = uuid::Uuid::now_v7();
    assert!(tracker.reserve_request("job".to_string(), alice));
    assert!(!tracker.reserve_request("job".to_string(), bob));
    assert!(tracker.reserve_request("job".to_string(), alice));
    assert_eq!(tracker.get("job").and_then(|i| i.owner_principal_id), Some(alice));
}
