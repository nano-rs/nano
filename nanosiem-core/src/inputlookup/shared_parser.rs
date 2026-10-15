// SPDX-License-Identifier: AGPL-3.0-or-later
//! Count rows before materializing remote JSON/CSV values. The byte cap alone
//! does not bound the allocation amplification of millions of tiny rows.
use super::{response_parser::parse_response, InputLookupFormat};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::cell::Cell;

const MAX_CSV_COLUMNS: usize = 1024;

const MAX_PARSED_VALUES: usize = 1_000_000;

pub(super) fn parse_shared_response(
    body: &str,
    format: InputLookupFormat,
    max_rows: usize,
) -> Result<Vec<Value>, &'static str> {
    let failed = "inputlookup response parse or row limit failure";
    let values = Cell::new(MAX_PARSED_VALUES);
    match format {
        InputLookupFormat::Json => {
            let mut bounded = serde_json::Deserializer::from_str(body);
            CountValues(&values)
                .deserialize(&mut bounded)
                .map_err(|_| {
                    "inputlookup response exceeds parsed value limit or has invalid JSON"
                })?;
            bounded.end().map_err(|_| failed)?;
            let mut deserializer = serde_json::Deserializer::from_str(body);
            CountRows(max_rows)
                .deserialize(&mut deserializer)
                .map_err(|_| failed)?;
            deserializer.end().map_err(|_| failed)?;
        }
        InputLookupFormat::Csv => {
            bound_csv_cells(body)?;
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .flexible(true)
                .trim(csv::Trim::All)
                .from_reader(body.as_bytes());
            for (index, record) in reader.records().enumerate() {
                record.map_err(|_| failed)?;
                if index >= max_rows {
                    return Err(failed);
                }
            }
        }
        InputLookupFormat::Ndjson => {
            for (index, line) in body.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                if index >= max_rows {
                    return Err(failed);
                }
                let mut bounded = serde_json::Deserializer::from_str(line);
                CountValues(&values)
                    .deserialize(&mut bounded)
                    .map_err(|_| {
                        "inputlookup response exceeds parsed value limit or has invalid JSON"
                    })?;
                bounded.end().map_err(|_| failed)?;
            }
        }
    }
    parse_response(body, format, max_rows).map_err(|_| failed)
}
// A single row can still contain a huge nested array, and CSV can contain
// millions of empty cells within the byte limit. Bound structural allocations
// before either parser creates owned values. JSON keys are visited without
// allocating strings; CSV delimiters are counted with the parser's quote rules.
fn bound_csv_cells(body: &str) -> Result<(), &'static str> {
    let bytes = body.as_bytes();
    let (mut index, mut cells, mut field_start, mut quoted) = (0, 1, true, false);
    let mut columns = 1;
    while index < bytes.len() {
        let c = bytes[index];
        if quoted {
            if c == b'"' {
                if bytes.get(index + 1) == Some(&b'"') {
                    index += 1;
                } else {
                    quoted = false;
                }
            }
        } else if c == b'"' && field_start {
            quoted = true;
            field_start = false;
        } else if matches!(c, b',' | b'\n' | b'\r') {
            if c == b',' {
                columns += 1;
                if columns > MAX_CSV_COLUMNS {
                    return Err("inputlookup response exceeds column limit");
                }
            } else {
                columns = 1;
            }
            cells += 1;
            if cells > MAX_PARSED_VALUES {
                return Err("inputlookup response exceeds parsed value limit");
            }
            field_start = true;
            if c == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
        } else {
            field_start = false;
        }
        index += 1;
    }
    Ok(())
}
struct CountValues<'a>(&'a Cell<usize>);
impl<'de> DeserializeSeed<'de> for CountValues<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.0.set(
            self.0
                .get()
                .checked_sub(1)
                .ok_or_else(|| <D::Error as serde::de::Error>::custom("parsed value limit"))?,
        );
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for CountValues<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded JSON values")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(CountValues(self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(CountValues(self.0))?;
        }
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct CountRows(usize);
impl<'de> DeserializeSeed<'de> for CountRows {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for CountRows {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded JSON rows")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut count = 0;
        while seq.next_element::<IgnoredAny>()?.is_some() {
            count += 1;
            if count > self.0 {
                return Err(serde::de::Error::custom("row limit"));
            }
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if matches!(key.as_str(), "data" | "results" | "items") {
                map.next_value_seed(CountRows(self.0))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
    // A wrapper key can hold a scalar rather than a row array; the ordinary
    // parser decides the final response shape after this allocation-free pass.
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_columns_are_bounded_per_record_including_headers() {
        let wide = ",".repeat(1024);
        for body in [format!("{wide}\n"), format!("name\n{wide}\n")] {
            assert!(parse_shared_response(&body, InputLookupFormat::Csv, 10).is_err());
        }
        let boundary = format!(
            "{}\n{}\n",
            vec!["h"; 1024].join(","),
            vec!["v"; 1024].join(",")
        );
        assert!(parse_shared_response(&boundary, InputLookupFormat::Csv, 10).is_ok());
    }

    #[test]
    fn nested_json_values_and_empty_csv_cells_cannot_amplify_allocations() {
        let json = format!(
            r#"{{"nested":[{}]}}"#,
            "0,".repeat(MAX_PARSED_VALUES).trim_end_matches(',')
        );
        for format in [InputLookupFormat::Json, InputLookupFormat::Ndjson] {
            assert!(parse_shared_response(&json, format, 10)
                .unwrap_err()
                .contains("parsed value limit"));
        }
        let csv = "a\n".repeat(MAX_PARSED_VALUES);
        assert!(parse_shared_response(&csv, InputLookupFormat::Csv, 10)
            .unwrap_err()
            .contains("parsed value limit"));
        assert!(
            bound_csv_cells(&format!("name\n\"{}\"\n", ",".repeat(MAX_PARSED_VALUES))).is_ok(),
            "commas inside a quoted value are not cells"
        );
    }

    #[test]
    fn row_caps_cover_json_arrays_wrappers_csv_and_ndjson() {
        for (body, format) in [
            ("[{}, {}, {}]", InputLookupFormat::Json),
            ("{\"data\":[{}, {}, {}]}", InputLookupFormat::Json),
            ("{\"items\":[{}, {}, {}]}", InputLookupFormat::Json),
            ("{\"results\":[{}, {}, {}]}", InputLookupFormat::Json),
            ("name\na\nb\nc\n", InputLookupFormat::Csv),
            ("{}\n{}\n{}\n", InputLookupFormat::Ndjson),
        ] {
            assert!(parse_shared_response(body, format, 2).is_err());
            assert_eq!(parse_shared_response(body, format, 3).unwrap().len(), 3);
        }
    }
}
