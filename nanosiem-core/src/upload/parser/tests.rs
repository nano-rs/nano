// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(test)]
mod tests {
    use crate::upload::parser::*;

    #[test]
    fn indicator_lists_detect_headers_and_keep_first_row() {
        let parser = FileParser::new();
        for (content, column) in [
            ("1.0.164.165\n1.0.212.159\n", "ip"),
            (
                "d41d8cd98f00b204e9800998ecf8427e\n900150983cd24fb0d6963f7d28e17f72\n",
                "hash",
            ),
            ("malware.example\nphishing.example\n", "domain"),
            ("2001:db8::1\n2001:db8::2\n", "ip"),
            ("192.0.2.0/24\n198.51.100.0/24\n", "cidr"),
            ("https://example.com/a\nhttps://example.com/b\n", "url"),
            ("analyst@example.com\nadmin@example.com\n", "email"),
        ] {
            assert!(!FileParser::detect_has_header(content.as_bytes(), ','));
            let result = parser
                .parse(content.as_bytes(), &ParserConfig::csv())
                .unwrap();
            assert_eq!(result.successful, 2);
            assert_eq!(result.headers, Some(vec![column.to_string()]));
        }
        for content in ["name,age\nAlice,30\n", "ip\n1.0.164.165\n"] {
            assert!(FileParser::detect_has_header(content.as_bytes(), ','));
            assert_eq!(
                parser
                    .parse(content.as_bytes(), &ParserConfig::csv())
                    .unwrap()
                    .successful,
                1
            );
        }
    }

    #[test]
    fn indicator_feeds_with_leading_comments_stay_headerless() {
        // A common feed shape: a comment banner, blank lines, then one
        // indicator per line. Detection and parsing must agree that the data
        // starts at the first IP, and neither may turn a comment into a column.
        let feed = "# updated 2026-11-02\n# source: example blocklist\n\n198.51.100.4\n203.0.113.9\n# trailing note\n192.0.2.10\n";
        assert!(!FileParser::detect_has_header(feed.as_bytes(), ','));
        let result = FileParser::new()
            .parse(feed.as_bytes(), &ParserConfig::csv())
            .unwrap();
        assert_eq!(result.headers, Some(vec!["ip".to_string()]));
        assert_eq!(result.successful, 3, "{:?}", result.errors);
        let ips: Vec<String> = result
            .records
            .iter()
            .map(|r| r.fields["ip"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ips, ["198.51.100.4", "203.0.113.9", "192.0.2.10"]);

        // The scheduler resolves the choice once from the first payload.
        assert!(!FileParser::resolve_has_header(feed.as_bytes(), &ParserConfig::csv()));

        // A legacy one-column table keeps its stored name on the same feed.
        let legacy: ParserConfig = serde_json::from_str("{\"format\":\"csv\"}").unwrap();
        let recovered =
            FileParser::config_for_existing_column(feed.as_bytes(), &legacy, "col_198_51_100_4");
        let result = FileParser::new().parse(feed.as_bytes(), &recovered).unwrap();
        assert_eq!(result.successful, 3);
        assert_eq!(result.headers, Some(vec!["col_198_51_100_4".to_string()]));
    }

    #[test]
    fn a_hash_that_does_not_open_the_file_is_data() {
        // Comment skipping is gated on the payload opening with one, so a
        // headered CSV whose values start with `#` is unchanged.
        let csv = "tag,count\n#ops,3\n#sec,5\n";
        let result = FileParser::new()
            .parse(csv.as_bytes(), &ParserConfig::csv())
            .unwrap();
        assert_eq!(result.headers, Some(vec!["tag".to_string(), "count".to_string()]));
        assert_eq!(result.successful, 2);
    }

    #[test]
    fn explicit_header_choice_and_legacy_column_recovery() {
        let content = b"1.0.164.165\n1.0.212.159\n";
        let config = ParserConfig::csv().with_headers(true);
        assert_eq!(
            FileParser::new()
                .parse(content, &config)
                .unwrap()
                .successful,
            1
        );
        let legacy: ParserConfig = serde_json::from_str("{\"format\":\"csv\"}").unwrap();
        let recovered = FileParser::config_for_existing_column(content, &legacy, "col_1_0_164_165");
        let result = FileParser::new().parse(content, &recovered).unwrap();
        assert_eq!(result.successful, 2);
        assert_eq!(result.headers, Some(vec!["col_1_0_164_165".to_string()]));
        let unknown = FileParser::new()
            .parse(b"alpha\nbeta\n", &ParserConfig::csv().with_headers(false))
            .unwrap();
        assert_eq!(unknown.headers, Some(vec!["value".to_string()]));
        assert_eq!(unknown.successful, 2);
    }

    // ==================== CSV Parser Tests ====================

    #[test]
    fn test_parse_csv_basic() {
        let parser = FileParser::new();
        let content = b"name,age,active\nAlice,30,true\nBob,25,false";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 0);
        assert_eq!(result.total_lines, 2);
        assert_eq!(
            result.headers,
            Some(vec![
                "name".to_string(),
                "age".to_string(),
                "active".to_string()
            ])
        );

        let first = &result.records[0];
        assert_eq!(first.get_str("name"), Some("Alice"));
        assert_eq!(first.get_i64("age"), Some(30));
        assert_eq!(first.get_bool("active"), Some(true));
    }

    #[test]
    fn test_parse_csv_with_quotes() {
        let parser = FileParser::new();
        let content = b"name,description\n\"John Doe\",\"A \"\"quoted\"\" value\"\nJane,Simple";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.records[0].get_str("name"), Some("John Doe"));
        assert_eq!(
            result.records[0].get_str("description"),
            Some("A \"quoted\" value")
        );
    }

    #[test]
    fn test_parse_csv_with_delimiter_in_quotes() {
        let parser = FileParser::new();
        let content = b"name,address\nAlice,\"123 Main St, Apt 4\"";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(
            result.records[0].get_str("address"),
            Some("123 Main St, Apt 4")
        );
    }

    #[test]
    fn test_parse_csv_tab_delimiter() {
        let parser = FileParser::new();
        let content = b"name\tage\nAlice\t30";
        let config = ParserConfig::csv().with_delimiter('\t');

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.records[0].get_str("name"), Some("Alice"));
        assert_eq!(result.records[0].get_i64("age"), Some(30));
    }

    #[test]
    fn test_parse_csv_pipe_delimiter() {
        let parser = FileParser::new();
        let content = b"name|age\nAlice|30";
        let config = ParserConfig::csv().with_delimiter('|');

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.records[0].get_str("name"), Some("Alice"));
    }

    #[test]
    fn test_parse_csv_no_headers() {
        let parser = FileParser::new();
        let content = b"Alice,30\nBob,25";
        let config = ParserConfig::csv().with_headers(false);

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(
            result.headers,
            Some(vec!["col_0".to_string(), "col_1".to_string()])
        );
        assert_eq!(result.records[0].get_str("col_0"), Some("Alice"));
    }

    #[test]
    fn test_parse_csv_custom_headers() {
        let parser = FileParser::new();
        let content = b"Alice,30\nBob,25";
        let config = ParserConfig::csv()
            .with_headers(false)
            .with_custom_headers(vec!["person".to_string(), "years".to_string()]);

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.records[0].get_str("person"), Some("Alice"));
        assert_eq!(result.records[0].get_i64("years"), Some(30));
    }

    #[test]
    fn test_parse_csv_rejects_row_wider_than_headers() {
        // NAN-1363: a too-wide row must NOT gain fabricated col_N keys
        let parser = FileParser::new();
        let content = b"name,age,active\nAlice,30,true\nBob,25,false,EXTRA";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].line_number, 3);
        assert!(result.errors[0]
            .error_message
            .contains("expected 3 fields, found 4"));
        // No record carries an invented column
        assert!(result
            .records
            .iter()
            .all(|r| !r.fields.contains_key("col_3")));
    }

    #[test]
    fn test_parse_csv_rejects_row_narrower_than_headers() {
        // NAN-1363: a too-short row must not silently drop fields
        let parser = FileParser::new();
        let content = b"name,age,active\nAlice,30\nBob,25,false";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].line_number, 2);
        assert!(result.errors[0]
            .error_message
            .contains("expected 3 fields, found 2"));
    }

    #[test]
    fn test_parse_csv_width_mismatch_fails_fast_when_strict() {
        let parser = FileParser::new();
        let content = b"name,age\nAlice,30,EXTRA\nBob,25";
        let config = ParserConfig::csv().with_skip_invalid(false);

        let err = parser.parse(content, &config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Line 2"), "got: {msg}");
        assert!(msg.contains("expected 2 fields, found 3"), "got: {msg}");
    }

    #[test]
    fn test_parse_csv_no_headers_width_set_by_first_record() {
        // Headerless: first record establishes the width, later rows must match
        let parser = FileParser::new();
        let content = b"Alice,30\nBob,25,EXTRA\nCarol,41";
        let config = ParserConfig::csv().with_headers(false);

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].line_number, 2);
        assert!(result.errors[0]
            .error_message
            .contains("expected 2 fields, found 3"));
    }

    #[test]
    fn test_parse_csv_custom_headers_width_enforced() {
        let parser = FileParser::new();
        let content = b"Alice,30,EXTRA\nBob,25";
        let config = ParserConfig::csv()
            .with_headers(false)
            .with_custom_headers(vec!["person".to_string(), "years".to_string()]);

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].line_number, 1);
        assert!(result.errors[0]
            .error_message
            .contains("expected 2 fields, found 3"));
    }

    #[test]
    fn test_parse_csv_with_newline_in_quotes() {
        let parser = FileParser::new();
        let content = b"name,note\nAlice,\"Line 1\nLine 2\"";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        assert_eq!(result.records[0].get_str("note"), Some("Line 1\nLine 2"));
    }

    #[test]
    fn test_parse_csv_type_inference() {
        let parser = FileParser::new();
        let content = b"str,int,float,bool_t,bool_f,null_val\nhello,42,3.14,true,false,";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config).unwrap();

        let record = &result.records[0];
        assert!(record.fields.get("str").unwrap().is_string());
        assert!(record.fields.get("int").unwrap().is_i64());
        assert!(record.fields.get("float").unwrap().is_f64());
        assert_eq!(record.fields.get("bool_t").unwrap().as_bool(), Some(true));
        assert_eq!(record.fields.get("bool_f").unwrap().as_bool(), Some(false));
        assert!(record.fields.get("null_val").unwrap().is_null());
    }

    // ==================== JSON Parser Tests ====================

    #[test]
    fn test_parse_json_array() {
        let parser = FileParser::new();
        let content = br#"[{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]"#;
        let config = ParserConfig::json();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 0);
        assert_eq!(result.total_lines, 2);
        assert_eq!(result.records[0].get_str("name"), Some("Alice"));
        assert_eq!(result.records[0].get_i64("age"), Some(30));
    }

    #[test]
    fn test_parse_json_nested_objects() {
        let parser = FileParser::new();
        let content = br#"[{"user": {"name": "Alice"}, "active": true}]"#;
        let config = ParserConfig::json();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 1);
        let user = result.records[0].fields.get("user").unwrap();
        assert!(user.is_object());
        assert_eq!(user.get("name").and_then(|v| v.as_str()), Some("Alice"));
    }

    #[test]
    fn test_parse_json_invalid_structure() {
        let parser = FileParser::new();
        let content = br#"{"not": "an array"}"#;
        let config = ParserConfig::json();

        let result = parser.parse(content, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_json_with_non_object_elements() {
        let parser = FileParser::new();
        let content = br#"[{"name": "Alice"}, "not an object", {"name": "Bob"}]"#;
        let config = ParserConfig::json();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].line_number, 2);
    }

    // ==================== NDJSON Parser Tests ====================

    #[test]
    fn test_parse_ndjson_basic() {
        let parser = FileParser::new();
        let content = b"{\"name\": \"Alice\", \"age\": 30}\n{\"name\": \"Bob\", \"age\": 25}";
        let config = ParserConfig::ndjson();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 0);
        assert_eq!(result.records[0].get_str("name"), Some("Alice"));
        assert_eq!(result.records[1].get_str("name"), Some("Bob"));
    }

    #[test]
    fn test_parse_ndjson_with_empty_lines() {
        let parser = FileParser::new();
        let content = b"{\"name\": \"Alice\"}\n\n{\"name\": \"Bob\"}\n";
        let config = ParserConfig::ndjson();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.total_lines, 2); // Empty lines not counted
    }

    #[test]
    fn test_parse_ndjson_with_malformed_lines() {
        let parser = FileParser::new();
        let content = b"{\"name\": \"Alice\"}\n{invalid json}\n{\"name\": \"Bob\"}";
        let config = ParserConfig::ndjson();

        let result = parser.parse(content, &config).unwrap();

        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].line_number, 2);
    }

    #[test]
    fn test_parse_ndjson_skip_invalid_false() {
        let parser = FileParser::new();
        let content = b"{\"name\": \"Alice\"}\n{invalid json}\n{\"name\": \"Bob\"}";
        let config = ParserConfig::ndjson().with_skip_invalid(false);

        let result = parser.parse(content, &config);
        assert!(result.is_err());
    }

    // ==================== Format Detection Tests ====================

    #[test]
    fn test_detect_format_json() {
        let content = br#"[{"name": "Alice"}]"#;
        assert_eq!(FileParser::detect_format(content), Some(FileFormat::Json));
    }

    #[test]
    fn test_detect_format_ndjson() {
        let content = b"{\"name\": \"Alice\"}\n{\"name\": \"Bob\"}";
        assert_eq!(FileParser::detect_format(content), Some(FileFormat::Ndjson));
    }

    #[test]
    fn test_detect_format_csv() {
        let content = b"name,age\nAlice,30";
        assert_eq!(FileParser::detect_format(content), Some(FileFormat::Csv));
    }

    // ==================== Encoding Tests ====================

    #[test]
    fn test_parse_utf8_with_bom() {
        let parser = FileParser::new();
        let mut content = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        content.extend_from_slice(b"name,age\nAlice,30");
        let config = ParserConfig::csv();

        let result = parser.parse(&content, &config).unwrap();
        assert_eq!(result.successful, 1);
    }

    #[test]
    fn test_parse_iso_8859_1() {
        let parser = FileParser::new();
        // "caf\u{e9}" in ISO-8859-1
        let content: Vec<u8> = vec![
            b'n', b'a', b'm', b'e', b'\n', b'c', b'a', b'f', 0xe9, // e\u{301} in ISO-8859-1
        ];
        let config = ParserConfig::csv().with_encoding("iso-8859-1");

        let result = parser.parse(&content, &config).unwrap();
        assert_eq!(result.successful, 1);
        assert_eq!(result.records[0].get_str("name"), Some("caf\u{e9}"));
    }

    // ==================== Preview Tests ====================

    #[test]
    fn test_preview_limits_records() {
        let parser = FileParser::new();
        let content = b"name\nAlice\nBob\nCharlie\nDiana\nEve";
        let config = ParserConfig::csv();

        let result = parser.preview(content, &config, 3).unwrap();

        assert_eq!(result.successful, 3);
        assert_eq!(result.records.len(), 3);
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_serialize_to_json() {
        let parser = FileParser::new();
        let content = br#"[{"name": "Alice", "age": 30}]"#;
        let config = ParserConfig::json();

        let result = parser.parse(content, &config).unwrap();
        let serialized = parser.serialize_to_json(&result).unwrap();

        // Parse back and verify
        let reparsed = parser.parse(serialized.as_bytes(), &config).unwrap();
        assert_eq!(reparsed.successful, 1);
        assert_eq!(reparsed.records[0].get_str("name"), Some("Alice"));
    }

    #[test]
    fn test_serialize_to_ndjson() {
        let parser = FileParser::new();
        let content = b"{\"name\": \"Alice\"}\n{\"name\": \"Bob\"}";
        let config = ParserConfig::ndjson();

        let result = parser.parse(content, &config).unwrap();
        let serialized = parser.serialize_to_ndjson(&result).unwrap();

        // Parse back and verify
        let reparsed = parser.parse(serialized.as_bytes(), &config).unwrap();
        assert_eq!(reparsed.successful, 2);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_file() {
        let parser = FileParser::new();
        let content = b"";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config);
        assert!(matches!(result, Err(ParseError::EmptyFile)));
    }

    #[test]
    fn test_csv_header_only() {
        let parser = FileParser::new();
        let content = b"name,age";
        let config = ParserConfig::csv();

        let result = parser.parse(content, &config);
        assert!(matches!(result, Err(ParseError::EmptyFile)));
    }

    #[test]
    fn test_json_empty_array() {
        let parser = FileParser::new();
        let content = b"[]";
        let config = ParserConfig::json();

        let result = parser.parse(content, &config);
        assert!(matches!(result, Err(ParseError::NoValidRecords)));
    }

    #[test]
    fn test_file_format_from_extension() {
        assert_eq!(FileFormat::from_extension("csv"), Some(FileFormat::Csv));
        assert_eq!(FileFormat::from_extension("CSV"), Some(FileFormat::Csv));
        assert_eq!(FileFormat::from_extension("tsv"), Some(FileFormat::Csv));
        assert_eq!(FileFormat::from_extension("json"), Some(FileFormat::Json));
        assert_eq!(
            FileFormat::from_extension("ndjson"),
            Some(FileFormat::Ndjson)
        );
        assert_eq!(
            FileFormat::from_extension("jsonl"),
            Some(FileFormat::Ndjson)
        );
        assert_eq!(FileFormat::from_extension("txt"), None);
    }
}
