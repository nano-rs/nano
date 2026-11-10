// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5163: the raw-SQL validator rejects ClickHouse aliases and siblings of
//! the server-identity functions, without rejecting ordinary analytic SQL that
//! uses the same words as columns or calls `toTimeZone`.

use super::validate_sql_query;

const ADDED: &[&str] = &[
    "user",
    "USER",
    "current_user",
    "session_user",
    "database",
    "current_database",
    "SCHEMA",
    "currentSchemas",
    "current_schemas",
    "version",
    "revision",
    "uptime",
    "timezone",
    "timeZone",
    "serverTimezone",
    "serverTimeZone",
    "currentRoles",
    "defaultRoles",
    "enabledProfiles",
    "defaultProfiles",
    "getServerPort",
    "fullHostName",
    "queryID",
    "query_id",
    "initialQueryID",
    "initial_query_id",
    "current_schema",
    "current_timezone",
    "authenticatedUser",
    "authUser",
    "pgGetUserById",
    "pg_get_userbyid",
    "getSettingOrDefault",
    "getServerSetting",
    "getMergeTreeSetting",
    "current_setting",
    "currentQueryID",
    "current_query_id",
    "connectionId",
    "connection_id",
    "initialQueryStartTime",
    "initial_query_start_time",
    "getClientHTTPHeader",
    "shardNum",
    "shardCount",
    "zookeeperSessionUptime",
    "filesystemUnreserved",
    // Pre-existing names reached through ClickHouse aliases.
    "hostname",
    "fullHostName",
    "FQDN",
];

#[test]
fn each_identity_alias_call_is_rejected() {
    for name in ADDED {
        for sql in [
            format!("SELECT {name}()"),
            format!("SELECT count() AS c, {name} () AS x FROM logs"),
            format!("SELECT * FROM logs WHERE src_host = {name}()"),
            format!("SELECT `{name}`() FROM logs"),
        ] {
            let err = validate_sql_query(&sql)
                .expect_err(&format!("must reject {sql}"));
            assert!(
                err.to_string().contains("Disallowed function"),
                "{sql}: {err}"
            );
        }
    }
}

#[test]
fn ordinary_sql_using_the_same_words_is_accepted() {
    for sql in [
        // Columns named like the functions, no call.
        "SELECT user, count() AS c FROM logs GROUP BY user ORDER BY c DESC LIMIT 10",
        "SELECT src_ip, user FROM logs WHERE user = 'admin' AND user IN ('a', 'b')",
        "SELECT count(user), uniq(user) FROM logs",
        "SELECT version, revision, timezone, uptime, database FROM logs LIMIT 5",
        "SELECT * FROM logs WHERE (user, src_host) IN (('a', 'h1'))",
        // Timezone conversion stays available.
        "SELECT toTimeZone(timestamp, 'UTC') AS ts FROM logs LIMIT 10",
        "SELECT toTimezone(timestamp, 'Europe/London') FROM logs LIMIT 10",
        "SELECT timeZoneOf(timestamp) FROM logs LIMIT 1",
        "SELECT toStartOfHour(timestamp, 'UTC') AS h, count() FROM logs GROUP BY h",
        // Log content mentioning the names.
        "SELECT * FROM logs WHERE message ILIKE '%version()%' OR message LIKE '%user(%'",
        "SELECT * FROM logs WHERE command_line LIKE '%current_user()%'",
        // Names as substrings of other functions / columns.
        "SELECT username, user_agent, dbversion FROM logs",
        "SELECT lower(user) AS u FROM logs",
        // Ordinary analytic functions near the denied names.
        "SELECT timezoneOf(timestamp), timeZoneOffset(timestamp), toUUID('00000000-0000-0000-0000-000000000000') FROM logs LIMIT 1",
        "SELECT port(url), domain(url), session_id, connection, shard FROM logs LIMIT 5",
        "SELECT uniq(session_id), any(query_id) FROM logs",
    ] {
        assert!(
            validate_sql_query(sql).is_ok(),
            "legitimate SQL rejected: {sql}: {:?}",
            validate_sql_query(sql)
        );
    }
}
