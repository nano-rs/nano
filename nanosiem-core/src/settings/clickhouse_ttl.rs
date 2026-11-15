// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse table-TTL and identifier helpers shared by open-core retention
//! code (Settings retention, the NAN-5448 TTL repair) and the enterprise
//! storage-tiering module.

/// ClickHouse identifiers nano uses: ASCII letters, digits and `_`, not
/// starting with a digit-only form that could be confused with a literal.
pub fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Days of the DELETE TTL in a `create_table_query`, if it has one
/// (`TTL timestamp + toIntervalDay(365) ...`). A move rule (`TO VOLUME` /
/// `TO DISK`) is not a delete and is skipped.
pub fn delete_ttl_days(create_table_query: &str) -> Option<u32> {
    let ttl_at = create_table_query.find(" TTL ")?;
    let ttl = &create_table_query[ttl_at + 5..];
    let ttl = ttl.split(" SETTINGS ").next().unwrap_or(ttl);
    ttl.split(',')
        .map(str::trim)
        .filter(|rule| !rule.contains(" TO VOLUME ") && !rule.contains(" TO DISK "))
        .find_map(|rule| {
            let start = rule.find("toIntervalDay(")? + "toIntervalDay(".len();
            let end = rule[start..].find(')')? + start;
            rule[start..end].trim().parse().ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_ttl_days_reads_the_delete_rule() {
        let ocsf = "CREATE TABLE nanosiem.ocsf_logs (`x` UInt8) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) \
                    ORDER BY x TTL timestamp + toIntervalDay(365) WHERE timestamp > '2000-01-01' \
                    SETTINGS index_granularity = 8192";
        assert_eq!(delete_ttl_days(ocsf), Some(365));
        let with_move = "CREATE TABLE t (x UInt8) ENGINE = MergeTree ORDER BY x \
                         TTL timestamp + toIntervalDay(7) TO VOLUME 'cold', timestamp + toIntervalDay(90) \
                         SETTINGS storage_policy = 'nano_tiered'";
        assert_eq!(delete_ttl_days(with_move), Some(90));
        assert_eq!(delete_ttl_days("CREATE TABLE t (x UInt8) ENGINE = MergeTree ORDER BY x"), None);
    }

    #[test]
    fn identifiers() {
        assert!(is_safe_identifier("signals_local"));
        assert!(!is_safe_identifier("a; DROP"));
        assert!(!is_safe_identifier(""));
    }
}
