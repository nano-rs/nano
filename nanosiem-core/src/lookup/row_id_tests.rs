// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use serde_json::json;

/// The id from the NAN-5715 repro: above 2^53, so a JS number rounds it.
const SNOWFLAKE: i64 = 7_529_336_958_272_102_401;

#[test]
fn listed_row_ids_are_strings_that_survive_a_browser() {
    let mut rows = vec![
        HashMap::from([("_row_id".to_string(), json!(SNOWFLAKE)), ("owner".to_string(), json!("eng"))]),
        HashMap::from([("_row_id".to_string(), json!(u64::MAX - 1))]),
        HashMap::from([("_row_id".to_string(), json!(7))]),
        HashMap::from([("owner".to_string(), json!("no id"))]),
    ];
    stringify_row_ids(&mut rows);
    assert_eq!(rows[0]["_row_id"], json!("7529336958272102401"));
    assert_eq!(rows[0]["owner"], json!("eng"));
    assert_eq!(rows[1]["_row_id"], json!((u64::MAX - 1).to_string()));
    assert_eq!(rows[2]["_row_id"], json!("7"));
    assert!(!rows[3].contains_key("_row_id"));
    // The JS rounding the bug hit: 7529336958272102401 -> 7529336958272102000.
    assert_ne!((SNOWFLAKE as f64) as i64, SNOWFLAKE);
}

#[test]
fn wire_ids_round_trip_including_bit_63() {
    let high_bit = (1u64 << 63 | 42) as i64; // idempotent-append ids
    for id in [SNOWFLAKE, 1, high_bit, -1] {
        assert_eq!(parse_row_id(&row_id_to_wire(id)), Some(id), "{id}");
    }
    // A signed spelling of a bit-63 id parses to the same bits.
    assert_eq!(parse_row_id(&high_bit.to_string()), Some(high_bit));
    assert_eq!(parse_row_id(" 12 "), Some(12));
    for bad in ["", "abc", "7.529336958272102e18", "18446744073709551616"] {
        assert_eq!(parse_row_id(bad), None, "{bad:?}");
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Ids {
    #[serde(deserialize_with = "deserialize_row_ids", serialize_with = "serialize_row_ids")]
    row_ids: Vec<i64>,
}

#[test]
fn request_ids_accept_strings_and_numbers_and_responses_send_strings() {
    let ids: Ids =
        serde_json::from_value(json!({"row_ids": ["7529336958272102401", 5, (1u64 << 63).to_string()]})).unwrap();
    assert_eq!(ids.row_ids, vec![SNOWFLAKE, 5, i64::MIN]);
    assert!(serde_json::from_value::<Ids>(json!({"row_ids": ["x"]})).is_err());
    assert_eq!(
        serde_json::to_value(&ids).unwrap(),
        json!({"row_ids": ["7529336958272102401", "5", "9223372036854775808"]})
    );
}
