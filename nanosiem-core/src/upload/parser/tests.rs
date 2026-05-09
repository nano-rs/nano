// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(test)]
mod tests {
    use crate::upload::parser::*;

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
