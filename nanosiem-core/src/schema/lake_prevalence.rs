// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3451: the scalar `prevalence_*` fields on an open-core lake.
//!
//! Lean signed parts carry the five scalars as physical ingest-time columns
//! (`nanosiem-lake-worker/src/part_ingest/prevalence.rs`, `stamp_from`). The
//! open-core (gen1) lake cannot: the pinned OCSF 1.9 contract rejects them at
//! admission (`prevalence_stamp.rs`), so the ingest stamper writes the same
//! facts into `enrichments[]` (`name = 'prevalence'`, `provider = 'nano'`,
//! `value = <artifact>`, `data.host_count`, `data.host_count_saturated`).
//! These expressions read them back as the scalars, so one nPL query
//! (`| where prevalence_min <= 3`) means the same thing on both backends.
//!
//! Per-artifact columns follow lean's `column_artifacts` exactly:
//!
//! | column                    | artifact                                                      |
//! |---------------------------|---------------------------------------------------------------|
//! | `prevalence_file_hash`    | first 64-hex value of `file.hashes`                           |
//! | `prevalence_process_hash` | first 64-hex value of `process.file.hashes`                   |
//! | `prevalence_dest_domain`  | `dst_endpoint.hostname`, else `query.hostname`; not an IPv4    |
//! | `prevalence_dest_ip`      | `dst_endpoint.ip` (private addresses are never stamped)        |
//!
//! Every artifact is `trim` + `lower`, the stamper's normalization. The value
//! is lean's: the stamped host count clamped to `1..=9998`, `9999` when the
//! host set saturated, a brand-new artifact is `1` (the stamper writes an
//! explicit `is_new` entry with `host_count: 1`). `65535` (N/A) when the row
//! has no such artifact, or the artifact carries no nano stamp (stamping
//! pending before the first generation, a private IP, a bare NetBIOS name).
//! Absence is never zero and never rare.
//!
//! `prevalence_min` is lean's `min` over the four columns whose artifact the
//! row carries, `9999` when it carries none. Here an N/A column contributes
//! `9999` to `least()` (the ClickHouse UDM rule), which is the same number
//! for every stamped row. The one difference: a row whose artifacts were
//! never stamped reads `9999` here where lean has no stamp at all. It is
//! never reported rare, which is the safe direction.

use super::types::FieldType;

/// The scalar names this module derives.
pub(super) const SCALARS: [&str; 5] = [
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
];

/// The aligned `enrichments[]` arrays every derivation needs. A lake snapshot
/// without all five has no prevalence stamp and the scalars stay unknown.
pub(crate) const STAMP_ARRAYS: [&str; 5] = [
    "enrichments.name",
    "enrichments.provider",
    "enrichments.value",
    "enrichments.data.host_count",
    "enrichments.data.host_count_saturated",
];

const NA: &str = "toUInt16(65535)";

pub(super) fn is_scalar(field: &str) -> bool {
    SCALARS.contains(&field)
}

pub(super) fn has_stamp(field_types: &impl Fn(&str) -> Option<FieldType>) -> bool {
    STAMP_ARRAYS
        .iter()
        .all(|field| field_types(field) == Some(FieldType::Array))
}

/// One artifact column: the SQL that yields the normalized artifact ('' when
/// the row has none) and the physical columns it reads.
struct Artifact {
    sql: String,
    inputs: Vec<&'static str>,
}

fn normalized(column: &str) -> String {
    format!(r#"lower(trimBoth(ifNull(toString("{column}"), '')))"#)
}

fn sha256_artifact(values: &'static str, available: &impl Fn(&str) -> bool) -> Option<Artifact> {
    available(values).then(|| Artifact {
        // Lean's `sha256_at`: the first SHA-256 of the hashes array. A
        // 64-hex digest is a SHA-256 by construction, which is also how the
        // stamper recognizes an unlabelled one.
        sql: format!(
            r#"ifNull(arrayFirst(h -> match(h, '^[0-9a-f]{{64}}$'), arrayMap(v -> lower(trimBoth(ifNull(toString(v), ''))), "{values}")), '')"#
        ),
        inputs: vec![values],
    })
}

fn artifact(column: &str, available: &impl Fn(&str) -> bool) -> Option<Artifact> {
    match column {
        "prevalence_file_hash" => sha256_artifact("file.hashes.value", available),
        "prevalence_process_hash" => sha256_artifact("process.file.hashes.value", available),
        "prevalence_dest_domain" => {
            let mut inputs = Vec::new();
            let mut sides = Vec::new();
            for path in ["dst_endpoint.hostname", "query.hostname"] {
                if available(path) {
                    inputs.push(path);
                    sides.push(normalized(path));
                }
            }
            // `dst_endpoint.hostname` wins when present; the DNS query name is
            // the fallback, never an additional artifact. A hostname that is
            // really an IPv4 literal is not a domain (and is not re-tried
            // against the fallback, matching lean).
            let host = match sides.as_slice() {
                [] => return None,
                [only] => only.clone(),
                [first, second] => format!("if({first} != '', {first}, {second})"),
                _ => unreachable!(),
            };
            Some(Artifact {
                sql: format!(
                    "if(match({host}, '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'), '', {host})"
                ),
                inputs,
            })
        }
        "prevalence_dest_ip" => available("dst_endpoint.ip").then(|| Artifact {
            sql: normalized("dst_endpoint.ip"),
            inputs: vec!["dst_endpoint.ip"],
        }),
        _ => None,
    }
}

/// The scalar for one artifact: its nano prevalence stamp mapped to lean's
/// sentinels. Matches provider AND artifact, so an IOC or another artifact's
/// stamp on the same row never leaks into this column.
fn scalar_sql(artifact: &str) -> String {
    let index = format!(
        r#"arrayFirstIndex((n, p, v) -> n = 'prevalence' AND p = 'nano' AND v = {artifact}, "enrichments.name", "enrichments.provider", "enrichments.value")"#
    );
    let hosts = format!(
        r#"toUInt64OrNull(toString(arrayElementOrNull("enrichments.data.host_count", {index})))"#
    );
    let saturated = format!(
        r#"toString(arrayElementOrNull("enrichments.data.host_count_saturated", {index}))"#
    );
    format!(
        "multiIf({artifact} = '' OR {index} = 0, {NA}, {saturated} IN ('1', 'true'), toUInt16(9999), isNull({hosts}), {NA}, toUInt16(least(9998, greatest(1, assumeNotNull({hosts})))))"
    )
}

fn column_sql(column: &str, available: &impl Fn(&str) -> bool) -> (String, Vec<&'static str>) {
    match artifact(column, available) {
        Some(artifact) => (scalar_sql(&artifact.sql), artifact.inputs),
        None => (NA.to_string(), Vec::new()),
    }
}

/// The derived expression for `field` and the physical columns it reads, or
/// `None` when `field` is not a prevalence scalar. The caller has already
/// established that the stamp arrays exist and that no physical column
/// (lean) shadows the name. `available` answers whether this lake can
/// address an artifact source column; one it cannot makes its column N/A.
pub(super) fn expression(
    field: &str,
    available: impl Fn(&str) -> bool,
) -> Option<(String, Vec<&'static str>)> {
    if !is_scalar(field) {
        return None;
    }
    let mut inputs: Vec<&'static str> = STAMP_ARRAYS.to_vec();
    let sql = if field == "prevalence_min" {
        let parts = SCALARS[..4]
            .iter()
            .map(|column| {
                let (sql, columns) = column_sql(column, &available);
                inputs.extend(columns);
                format!("if(({sql}) = 65535, toUInt16(9999), {sql})")
            })
            .collect::<Vec<_>>();
        format!("toUInt16(least({}))", parts.join(", "))
    } else {
        let (sql, columns) = column_sql(field, &available);
        inputs.extend(columns);
        sql
    };
    inputs.sort_unstable();
    inputs.dedup();
    Some((sql, inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(_: &str) -> bool {
        true
    }

    #[test]
    fn only_the_five_scalars_are_derived() {
        for field in SCALARS {
            assert!(expression(field, all).is_some(), "{field}");
        }
        for field in [
            "prevalence_url",
            "prevalence",
            "enrichments.value",
            "dst_endpoint.ip",
        ] {
            assert!(expression(field, all).is_none(), "{field}");
        }
    }

    /// Each column matches the stamp by provider AND its own artifact, so an
    /// IOC entry or another artifact's stamp on the row cannot leak in.
    #[test]
    fn each_column_matches_its_own_artifact_and_the_nano_provider() {
        for (field, artifact) in [
            ("prevalence_file_hash", r#""file.hashes.value""#),
            ("prevalence_process_hash", r#""process.file.hashes.value""#),
            ("prevalence_dest_domain", r#""dst_endpoint.hostname""#),
            ("prevalence_dest_ip", r#""dst_endpoint.ip""#),
        ] {
            let (sql, _) = expression(field, all).unwrap();
            assert!(
                sql.contains("n = 'prevalence' AND p = 'nano'"),
                "{field}: {sql}"
            );
            assert!(sql.contains(artifact), "{field}: {sql}");
            for other in [
                "file.hashes.value",
                "dst_endpoint.ip",
                "dst_endpoint.hostname",
            ] {
                if !artifact.contains(other) {
                    assert!(
                        !sql.contains(&format!("\"{other}\"")),
                        "{field} reads {other}: {sql}"
                    );
                }
            }
            // Lean's sentinels: N/A, common, and the 1..=9998 clamp.
            for sentinel in [
                "toUInt16(65535)",
                "toUInt16(9999)",
                "least(9998, greatest(1,",
            ] {
                assert!(sql.contains(sentinel), "{field} lacks {sentinel}: {sql}");
            }
        }
    }

    /// `prevalence_min` folds N/A columns to 9999 before `least()`, so an
    /// absent artifact never drags the row's minimum to 65535 and a row with
    /// no artifact at all reads 9999, as lean stamps it.
    #[test]
    fn prevalence_min_is_least_over_columns_with_na_as_common() {
        let (sql, inputs) = expression("prevalence_min", all).unwrap();
        assert!(sql.starts_with("toUInt16(least("), "{sql}");
        assert_eq!(sql.matches("= 65535, toUInt16(9999)").count(), 4, "{sql}");
        for input in [
            "file.hashes.value",
            "process.file.hashes.value",
            "dst_endpoint.hostname",
            "query.hostname",
            "dst_endpoint.ip",
        ] {
            assert!(inputs.contains(&input), "{input}");
        }
    }

    /// A snapshot without an artifact's source column makes that column N/A
    /// and never declares the missing column as an input.
    #[test]
    fn missing_artifact_sources_are_na_not_phantom_inputs() {
        let available = |name: &str| !name.contains("hashes") && name != "query.hostname";
        let (hash, inputs) = expression("prevalence_file_hash", available).unwrap();
        assert_eq!(hash, NA);
        assert_eq!(inputs, {
            let mut stamp = STAMP_ARRAYS.to_vec();
            stamp.sort_unstable();
            stamp
        });
        let (domain, inputs) = expression("prevalence_dest_domain", available).unwrap();
        assert!(domain.contains("dst_endpoint.hostname") && !domain.contains("query.hostname"));
        assert!(inputs.contains(&"dst_endpoint.hostname") && !inputs.contains(&"query.hostname"));
        let (min, inputs) = expression("prevalence_min", available).unwrap();
        assert!(!min.contains("hashes"), "{min}");
        assert!(!inputs.iter().any(|input| input.contains("hashes")));
    }

    /// The artifact normalization is the stamper's (`trim` + `lower`), the
    /// hash is the first 64-hex digest, and an IPv4 literal is no domain.
    #[test]
    fn artifacts_use_the_stamper_normalization() {
        let (hash, _) = expression("prevalence_file_hash", all).unwrap();
        assert!(hash.contains("match(h, '^[0-9a-f]{64}$')"), "{hash}");
        assert!(
            hash.contains("lower(trimBoth(ifNull(toString(v), '')))"),
            "{hash}"
        );
        let (domain, _) = expression("prevalence_dest_domain", all).unwrap();
        assert!(
            domain.contains("'^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'"),
            "{domain}"
        );
        let (ip, _) = expression("prevalence_dest_ip", all).unwrap();
        assert!(
            ip.contains(r#"lower(trimBoth(ifNull(toString("dst_endpoint.ip"), '')))"#),
            "{ip}"
        );
    }
}
