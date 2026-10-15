// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2885: the exact key fence of the lean-lake part model's two owner
//! writer classes (`docs-internal/NAN-2865-part-contract.md` section 1).
//!
//! One Rust copy of the rule, shared by the control-side copy registrar
//! (`shared_r2_copy_registration`) and the lake worker's writer
//! identity checks. PostgreSQL enforces the same rule in
//! `nano_shared.shared_r2_writer_physical_key_matches` (migration
//! 9003460); the platform's `parseLakePartKey` / `lakePartObjectKeyMatches` is the
//! owner-side mirror.
//!
//! Everything lives under `lake/parts/v1/tenant={tenant_uuid}/`:
//!
//! | writer class    | key family                 | key                                  |
//! |-----------------|----------------------------|--------------------------------------|
//! | `lake_part_log` | `lake_part_log_entry`      | `log/entries/{seq:020}.json`         |
//! | `lake_part`     | `lake_part_log_checkpoint` | `log/checkpoints/{seq:020}.json`     |
//! | `lake_part`     | `lake_part_file`           | `parts/{level}/{yyyy}/{mm}/{dd}/{hh}/{part_id}/{file}` |
//!
//! A part `{file}` is one of the fixed files, `data-{i:05}.parquet`,
//! `tokens-{i:05}.nti`, or (NAN-3128, as 9010420 admits them) a
//! `{ranges,locators,entities,uids}-{i:05}.json` sidecar, with `i < 1000`.
//!
//! `log/HEAD` is never admitted (mutable, non-authoritative). A part file's
//! event hour is its key's date-path hour (a `d` part: `hh = 00`, the day's
//! first hour). A log entry or checkpoint declares its append hour, which the
//! key cannot prove; control bounds it against the reservation time instead.

use chrono::{NaiveDate, Utc};

pub const LAKE_PART_LOG_CLASS: &str = "lake_part_log";
pub const LAKE_PART_CLASS: &str = "lake_part";
pub const LAKE_PART_LOG_ENTRY_FAMILY: &str = "lake_part_log_entry";
pub const LAKE_PART_LOG_CHECKPOINT_FAMILY: &str = "lake_part_log_checkpoint";
pub const LAKE_PART_FILE_FAMILY: &str = "lake_part_file";
/// Log entries and checkpoints are single-PUT objects of at most this size.
pub const MAX_LAKE_PART_LOG_OBJECT_BYTES: u64 = 4 * 1024 * 1024;

const ROOT: &str = "lake/parts/v1/tenant=";
const LEVELS: [&str; 4] = ["l0", "m", "h", "d"];
const FIXED_FILES: [&str; 5] = [
    "provenance.json",
    "partials/rollup.parquet",
    "partials/prevalence.parquet",
    "partials/entity_ranges.parquet",
    "partials/risk.parquet",
];
const MAX_DATA_FILES: u32 = 1_000;
/// NAN-3128: `{name}-{index:05}.json` sidecars beside each data file (migration 9010420).
const SIDECAR_FILES: [&str; 4] = ["ranges", "locators", "entities", "uids"];

/// True iff `writer_class` or `key_family` names the part model. A request
/// that names one but not a matching other is refused by [`key_matches`].
pub fn is_lake_part(writer_class: &str, key_family: &str) -> bool {
    matches!(writer_class, LAKE_PART_LOG_CLASS | LAKE_PART_CLASS)
        || matches!(
            key_family,
            LAKE_PART_LOG_ENTRY_FAMILY | LAKE_PART_LOG_CHECKPOINT_FAMILY | LAKE_PART_FILE_FAMILY
        )
}

/// The exact class/family pairs the part model admits.
pub fn class_accepts(writer_class: &str, key_family: &str) -> bool {
    matches!(
        (writer_class, key_family),
        (LAKE_PART_LOG_CLASS, LAKE_PART_LOG_ENTRY_FAMILY)
            | (LAKE_PART_CLASS, LAKE_PART_LOG_CHECKPOINT_FAMILY)
            | (LAKE_PART_CLASS, LAKE_PART_FILE_FAMILY)
    )
}

/// The exact key fence. `tenant_uuid` is the binding's own immutable tenant
/// UUID (lowercase, hyphenated v4); `event_hour` is hours since the Unix epoch.
pub fn key_matches(
    key: &str,
    writer_class: &str,
    key_family: &str,
    tenant_uuid: &str,
    event_hour: i64,
) -> bool {
    if !class_accepts(writer_class, key_family) || !is_v4_uuid(tenant_uuid) {
        return false;
    }
    let Some(rest) = key
        .strip_prefix(ROOT)
        .and_then(|rest| rest.strip_prefix(tenant_uuid))
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        return false;
    };
    match key_family {
        LAKE_PART_LOG_ENTRY_FAMILY => sequence_file(rest, "log/entries/"),
        LAKE_PART_LOG_CHECKPOINT_FAMILY => sequence_file(rest, "log/checkpoints/"),
        _ => part_file_hour(rest) == Some(event_hour),
    }
}

/// `{prefix}{seq:020}.json` with `seq` a u64.
fn sequence_file(rest: &str, prefix: &str) -> bool {
    rest.strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|seq| {
            seq.len() == 20 && seq.bytes().all(|byte| byte.is_ascii_digit()) && seq.parse::<u64>().is_ok()
        })
}

/// The date-path hour (hours since the epoch) of an admissible part file key.
fn part_file_hour(rest: &str) -> Option<i64> {
    let mut segments = rest.splitn(8, '/');
    if segments.next()? != "parts" {
        return None;
    }
    let level = segments.next()?;
    let (year, month, day, hour) = (segments.next()?, segments.next()?, segments.next()?, segments.next()?);
    let part_id = segments.next()?;
    let file = segments.next()?;
    if !LEVELS.contains(&level)
        || !digits(year, 4)
        || !digits(month, 2)
        || !digits(day, 2)
        || !digits(hour, 2)
        || !valid_part_id(part_id)
        || !valid_file(file)
        || (level == "d" && hour != "00")
    {
        return None;
    }
    let (year, month, day, hour) = (
        year.parse::<i32>().ok()?,
        month.parse::<u32>().ok()?,
        day.parse::<u32>().ok()?,
        hour.parse::<u32>().ok()?,
    );
    if year < 1970 {
        return None;
    }
    let at = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, 0, 0)?;
    Some(at.and_local_timezone(Utc).single()?.timestamp().div_euclid(3_600))
}

fn digits(value: &str, width: usize) -> bool {
    value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `{created_unix_ms:013}-{16 lowercase hex}`.
fn valid_part_id(value: &str) -> bool {
    value.split_once('-').is_some_and(|(millis, random)| {
        digits(millis, 13)
            && random.len() == 16
            && random.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The closed file-name set of one part (contract r2 sections 2-4).
fn valid_file(file: &str) -> bool {
    if FIXED_FILES.contains(&file) {
        return true;
    }
    // NAN-3801: the counts-only backfill's signed count record and its
    // count file (`counts-v2.json`, `counts-v2-[0-9a-f]{16}.parquet`).
    if file == "counts-v2.json" {
        return true;
    }
    if let Some(digest) = file.strip_prefix("counts-v2-").and_then(|rest| rest.strip_suffix(".parquet")) {
        return digest.len() == 16 && digest.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    }
    if let Some(digest) = file
        .strip_prefix("provenance.pending.")
        .and_then(|rest| rest.strip_suffix(".json"))
    {
        return digest.len() == 64 && digest.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    }
    // NAN-3128: the native writer's per-data-file sidecars, as migration 9010420 admits them
    // (`(ranges|locators|entities|uids)-00[0-9]{3}.json`).
    let sidecar = || {
        SIDECAR_FILES.iter().find_map(|name| {
            file.strip_prefix(*name)
                .and_then(|rest| rest.strip_prefix('-'))
                .and_then(|rest| rest.strip_suffix(".json"))
        })
    };
    let index = file
        .strip_prefix("data-")
        .and_then(|rest| rest.strip_suffix(".parquet"))
        .or_else(|| file.strip_prefix("tokens-").and_then(|rest| rest.strip_suffix(".nti")))
        .or_else(sidecar);
    index.is_some_and(|index| digits(index, 5) && index.parse::<u32>().is_ok_and(|i| i < MAX_DATA_FILES))
}

fn is_v4_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.get_version_num() == 4
            && parsed.to_string() == value
            && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "6f1c1e8a-2b3c-4d5e-8f90-0123456789ab";
    const OTHER: &str = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d";
    /// 2026-09-25T13:00:00Z.
    const HOUR: i64 = 1_790_341_200 / 3_600;
    /// 2026-09-25T00:00:00Z.
    const DAY: i64 = 1_790_294_400 / 3_600;

    fn part(level: &str, date: &str, file: &str) -> String {
        format!("lake/parts/v1/tenant={TENANT}/parts/{level}/{date}/1790341200123-9f86d081884c7d65/{file}")
    }

    #[test]
    fn log_entries_are_lake_part_log_only() {
        let key = format!("lake/parts/v1/tenant={TENANT}/log/entries/00000000000000000042.json");
        assert!(key_matches(&key, "lake_part_log", "lake_part_log_entry", TENANT, HOUR));
        // Any append hour: the key cannot prove it (control bounds it by time).
        assert!(key_matches(&key, "lake_part_log", "lake_part_log_entry", TENANT, HOUR - 7));
        assert!(!key_matches(&key, "lake_part", "lake_part_log_entry", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part", "lake_part_log_checkpoint", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part_log", "lake_part_file", TENANT, HOUR));
        let max = format!("lake/parts/v1/tenant={TENANT}/log/entries/18446744073709551615.json");
        assert!(key_matches(&max, "lake_part_log", "lake_part_log_entry", TENANT, HOUR));
        for bad in [
            format!("lake/parts/v1/tenant={TENANT}/log/entries/18446744073709551616.json"),
            format!("lake/parts/v1/tenant={TENANT}/log/entries/42.json"),
            format!("lake/parts/v1/tenant={TENANT}/log/entries/0000000000000000004a.json"),
            format!("lake/parts/v1/tenant={TENANT}/log/HEAD"),
            format!("lake/parts/v1/tenant={OTHER}/log/entries/00000000000000000042.json"),
            format!("x/lake/parts/v1/tenant={TENANT}/log/entries/00000000000000000042.json"),
        ] {
            assert!(!key_matches(&bad, "lake_part_log", "lake_part_log_entry", TENANT, HOUR), "{bad}");
        }
    }

    #[test]
    fn checkpoints_are_lake_part_only() {
        let key = format!("lake/parts/v1/tenant={TENANT}/log/checkpoints/00000000000000000042.json");
        assert!(key_matches(&key, "lake_part", "lake_part_log_checkpoint", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part_log", "lake_part_log_checkpoint", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part_log", "lake_part_log_entry", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part", "lake_part_file", TENANT, HOUR));
    }

    #[test]
    fn part_files_use_the_closed_set_and_their_date_path_hour() {
        for file in [
            "data-00000.parquet", "data-00999.parquet", "tokens-00000.nti", "tokens-00999.nti",
            "ranges-00000.json", "locators-00000.json", "entities-00007.json", "uids-00999.json",
            "provenance.json", "partials/rollup.parquet", "partials/prevalence.parquet",
            "partials/entity_ranges.parquet", "partials/risk.parquet",
            "provenance.pending.9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.json",
            "counts-v2.json", "counts-v2-0123456789abcdef.parquet",
        ] {
            let key = part("l0", "2026/09/25/13", file);
            assert!(key_matches(&key, "lake_part", "lake_part_file", TENANT, HOUR), "{file}");
            assert!(!key_matches(&key, "lake_part", "lake_part_file", TENANT, HOUR + 1), "{file}");
            assert!(!key_matches(&key, "lake_part_log", "lake_part_file", TENANT, HOUR), "{file}");
            assert!(!key_matches(&key, "lake_part", "lake_part_file", OTHER, HOUR), "{file}");
        }
        for file in [
            "data-01000.parquet", "tokens-01000.nti", "data.parquet", "tokens.nti", "data-0000.parquet",
            "partials/other.parquet", "provenance.pending.ABC.json", "provenance.json/x",
            "ranges-01000.json", "ranges-0000.json", "ranges.json", "ranges-00000.parquet", "ranges00000.json",
            "other-00000.json", "uids-00000.nti", "locators--0001.json",
            "counts-v2-0123456789ABCDEF.parquet", "counts-v2-0123456789abcde.parquet", "counts-v2.parquet",
            "counts-v3.json", "counts-v2-0123456789abcdef.json",
        ] {
            assert!(!key_matches(&part("l0", "2026/09/25/13", file), "lake_part", "lake_part_file", TENANT, HOUR), "{file}");
        }
        assert!(key_matches(&part("m", "2026/09/25/13", "data-00000.parquet"), "lake_part", "lake_part_file", TENANT, HOUR));
        assert!(key_matches(&part("h", "2026/09/25/13", "data-00000.parquet"), "lake_part", "lake_part_file", TENANT, HOUR));
        assert!(!key_matches(&part("x", "2026/09/25/13", "data-00000.parquet"), "lake_part", "lake_part_file", TENANT, HOUR));
    }

    #[test]
    fn day_parts_are_hour_zero_and_dates_are_real() {
        let day = part("d", "2026/09/25/00", "data-00000.parquet");
        assert!(key_matches(&day, "lake_part", "lake_part_file", TENANT, DAY));
        assert!(!key_matches(&day, "lake_part", "lake_part_file", TENANT, DAY + 1));
        assert!(!key_matches(&part("d", "2026/09/25/13", "data-00000.parquet"), "lake_part", "lake_part_file", TENANT, HOUR));
        for date in ["2026/02/30/00", "2026/13/01/00", "2026/00/01/00", "2026/09/00/00", "2026/09/25/24", "0000/01/01/00", "2026/9/25/13"] {
            assert!(!key_matches(&part("l0", date, "data-00000.parquet"), "lake_part", "lake_part_file", TENANT, HOUR), "{date}");
        }
        let leap = part("l0", "2028/02/29/05", "data-00000.parquet");
        let leap_hour = NaiveDate::from_ymd_opt(2028, 2, 29).unwrap().and_hms_opt(5, 0, 0).unwrap()
            .and_utc().timestamp() / 3_600;
        assert!(key_matches(&leap, "lake_part", "lake_part_file", TENANT, leap_hour));
    }

    #[test]
    fn other_families_and_non_v4_tenants_are_refused() {
        let key = part("l0", "2026/09/25/13", "data-00000.parquet");
        assert!(!key_matches(&key, "primary_iceberg_data", "lake_part_file", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part", "iceberg_data", TENANT, HOUR));
        assert!(!key_matches(&key, "lake_part", "lake_part_file", &TENANT.to_uppercase(), HOUR));
        assert!(is_lake_part("staged_hot_tail", "lake_part_file"));
        assert!(!is_lake_part("staged_hot_tail", "staged_hot_tail"));
    }
}
