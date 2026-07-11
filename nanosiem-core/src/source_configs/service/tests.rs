// SPDX-License-Identifier: AGPL-3.0-or-later
    use super::*;
    use super::super::types::{RoutingRule, SourceConfiguration, SourceConfigurationWithRules};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_config(config_type: &str, rules: Vec<RoutingRule>) -> SourceConfigurationWithRules {
        let now = Utc::now();
        SourceConfigurationWithRules {
            config: SourceConfiguration {
                id: Uuid::new_v4(),
                name: "test_source".to_string(),
                description: None,
                config_type: config_type.to_string(),
                connection_config: serde_json::json!({}),
                credential_id: None,
                enabled: true,
                deployed: false,
                deployed_at: None,
                created_at: now,
                updated_at: now,
                events_24h: None,
                bytes_per_day_24h: None,
                last_event_at: None,
            },
            routing_rules: rules,
        }
    }

    fn make_rule(
        priority: i32,
        match_field: &str,
        match_type: &str,
        match_value: Option<&str>,
        target: &str,
    ) -> RoutingRule {
        RoutingRule {
            id: Uuid::new_v4(),
            source_configuration_id: Uuid::nil(),
            priority,
            match_field: match_field.to_string(),
            match_type: match_type.to_string(),
            match_value: match_value.map(|s| s.to_string()),
            target_source_type: target.to_string(),
            created_at: Utc::now(),
            fires_24h: None,
            last_fired_at: None,
        }
    }

    /// Bug shape: pull-source rule with match_field=source_type +
    /// match_type=exact must coalesce into an unconditional default assignment,
    /// not the always-false `if .source_type == X` block.
    #[test]
    fn pull_source_with_buggy_source_type_rule_coalesces_to_default() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("limacharlie_edr"),
                "limacharlie_edr",
            )],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected unconditional default assignment, got:\n{}",
            vrl
        );
        assert!(
            !vrl.contains("if .source_type =="),
            "expected no tautological if-block, got:\n{}",
            vrl
        );
        assert!(
            !vrl.contains("\"unknown\""),
            "expected no fallthrough to unknown, got:\n{}",
            vrl
        );
    }

    /// Regression guard: a properly-shaped pull-source default rule still
    /// emits the unconditional assignment.
    #[test]
    fn pull_source_with_proper_default_rule_emits_unconditional() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(1000, "source_type", "default", None, "limacharlie_edr")],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected unconditional default assignment, got:\n{}",
            vrl
        );
        // Narrow assertion: ensure no source_type conditional. The
        // forwarded_via stamp (NAN-884 K-6) introduces an unrelated
        // `if !is_object(.metadata)` guard which is fine here.
        assert!(
            !vrl.contains("if .source_type"),
            "expected no source_type conditional, got:\n{}",
            vrl
        );
    }

    /// Regression guard: pull-source rules matching on a real inbound field
    /// (Kafka topic) still emit the if-block as before.
    #[test]
    fn pull_source_with_native_field_match_emits_if_block() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "exact", Some("audit-logs"), "aws_cloudtrail"),
                make_rule(1000, "source_type", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains("if .topic == \"audit-logs\""),
            "expected topic conditional, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"aws_cloudtrail\""),
            "expected matched-target assignment, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"unknown\""),
            "expected unknown fallthrough, got:\n{}",
            vrl
        );
    }

    /// Regression guard: HTTP (system-level) sources keep their
    /// passthrough-unmatched semantics — match_field=source_type rules are
    /// legitimate here because the X-Source-Type header populates
    /// `.source_type` upstream.
    #[test]
    fn http_source_with_source_type_rules_preserves_passthrough() {
        let config = make_config(
            "http",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("aws_cloudtrail_raw"),
                "aws_cloudtrail",
            )],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "source_type_extract", "route", true,
        );

        assert!(
            vrl.contains("if .source_type == \"aws_cloudtrail_raw\""),
            "expected source_type if-block for system-level source, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"aws_cloudtrail\""),
            "expected matched-target assignment, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains("passthrough"),
            "expected passthrough comment for system-level fallthrough, got:\n{}",
            vrl
        );
        // Must NOT degrade to the "unknown" default that pull sources use
        assert!(
            !vrl.contains(".source_type = \"unknown\""),
            "system-level source must not fallthrough to unknown, got:\n{}",
            vrl
        );
    }

    // ------------------------------------------------------------------
    // Coercion helpers (unit-level, no DB required)
    // ------------------------------------------------------------------

    #[test]
    fn coerce_pull_source_buggy_shape_to_default() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("gcp_pubsub", "source_type", &mut mt);
        assert_eq!(mt, "default");
    }

    #[test]
    fn coerce_leaves_native_field_untouched() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("kafka", "topic", &mut mt);
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_leaves_system_level_untouched() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("http", "source_type", &mut mt);
        assert_eq!(mt, "exact");

        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("vector", "source_type", &mut mt);
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_leaves_already_default_untouched() {
        let mut mt = "default".to_string();
        SourceConfigService::coerce_pull_source_match_type("gcp_pubsub", "source_type", &mut mt);
        assert_eq!(mt, "default");
    }

    // ------------------------------------------------------------------
    // Nested-path generator (NAN-649): match_field=attributes.source_type
    // emits `if .attributes.source_type == "X"`, not the buggy single-segment
    // shape that pre-NAN-649 generators silently truncated to.
    // ------------------------------------------------------------------

    #[test]
    fn pull_source_with_nested_path_match_field_emits_dotted_access() {
        let config = make_config(
            "gcp_pubsub",
            vec![
                make_rule(
                    10,
                    "attributes.source_type",
                    "exact",
                    Some("limacharlie_edr"),
                    "limacharlie_edr",
                ),
                make_rule(1000, "subscription", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(&config, "src", "route", false);

        assert!(
            vrl.contains("if .attributes.source_type == \"limacharlie_edr\""),
            "expected dotted-path conditional, got:\n{vrl}",
        );
        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected matched-target assignment, got:\n{vrl}",
        );
    }

    #[test]
    fn kafka_with_headers_path_match_field_emits_coerced_access() {
        // NAN-884 K-7: Vector's kafka source emits `.headers` as
        // `Object(String, Bytes)`; a raw `.headers.source_type == "X"`
        // comparison is `Bytes == String` and is always-false. The
        // generator must wrap header accesses in `to_string(...) ?? ""`
        // so the comparison actually fires.
        let config = make_config(
            "kafka",
            vec![
                make_rule(
                    10,
                    "headers.source_type",
                    "exact",
                    Some("audit_logs"),
                    "aws_cloudtrail",
                ),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(&config, "src", "route", false);

        assert!(
            vrl.contains(
                "if (to_string(.headers.source_type) ?? \"\") == \"audit_logs\""
            ),
            "expected coerced headers.source_type conditional, got:\n{vrl}",
        );
        // Regression guard: the broken raw form must not slip back in.
        assert!(
            !vrl.contains("if .headers.source_type =="),
            "raw .headers access regressed (Bytes vs String always-false), got:\n{vrl}",
        );
    }

    // ------------------------------------------------------------------
    // Safe-VRL-path validation (NAN-649): rejects injection attempts on
    // match_field. Coexists with NAN-648 coercion — when coercion converts
    // the rule to default the validation no-ops.
    // ------------------------------------------------------------------

    #[test]
    fn validate_match_field_path_accepts_simple_identifier() {
        SourceConfigService::validate_match_field_path("source_type", "exact").unwrap();
        SourceConfigService::validate_match_field_path("topic", "prefix").unwrap();
        SourceConfigService::validate_match_field_path("_private", "exact").unwrap();
    }

    #[test]
    fn validate_match_field_path_accepts_nested_path() {
        SourceConfigService::validate_match_field_path("attributes.source_type", "exact").unwrap();
        SourceConfigService::validate_match_field_path("a.b.c.d", "exact").unwrap();
    }

    #[test]
    fn validate_match_field_path_rejects_injection_with_quote_and_assignment() {
        // The exact attempt called out in the Linear acceptance criteria.
        let err = SourceConfigService::validate_match_field_path(
            "X Y'; .source_type = \"hax\"",
            "exact",
        )
        .expect_err("VRL-injection must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not a valid VRL path"),
            "expected VRL-path error, got: {msg}",
        );
    }

    #[test]
    fn validate_match_field_path_rejects_whitespace() {
        SourceConfigService::validate_match_field_path("foo bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path(" leading", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("trailing ", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_double_dot_and_leading_dot() {
        SourceConfigService::validate_match_field_path(".leading_dot", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("trailing.", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("a..b", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_special_chars() {
        SourceConfigService::validate_match_field_path("foo[0]", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo-bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo+bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo\"bar", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_empty() {
        SourceConfigService::validate_match_field_path("", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_skips_for_default_match_type() {
        // Default rules ignore match_field — generator never interpolates it.
        // We allow legacy/coerced match_field=source_type rules through.
        SourceConfigService::validate_match_field_path("source_type", "default").unwrap();
        SourceConfigService::validate_match_field_path("anything garbage", "default").unwrap();
    }

    #[test]
    fn validate_match_field_path_rejects_first_char_digit() {
        SourceConfigService::validate_match_field_path("0bad", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("a.0bad", "exact").unwrap_err();
    }

    #[test]
    fn coerce_and_validate_match_coerces_then_skips_validation() {
        // Pull source + match_field=source_type + non-default match_type:
        // coercion fires (match_type → "default"), validation then skips
        // (default rules don't reach the field-interpolation path).
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_and_validate_match("gcp_pubsub", "source_type", &mut mt)
            .unwrap();
        assert_eq!(mt, "default");
    }

    #[test]
    fn coerce_and_validate_match_validates_when_no_coercion() {
        // Push source: coercion is a no-op, validation runs and rejects junk.
        let mut mt = "exact".to_string();
        let err = SourceConfigService::coerce_and_validate_match(
            "http",
            "foo bar; .x = \"hax\"",
            &mut mt,
        )
        .unwrap_err();
        assert!(matches!(err, SourceConfigServiceError::InvalidConfig(_)));
        // No coercion happened.
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_and_validate_match_passes_clean_path() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_and_validate_match(
            "kafka",
            "attributes.source_type",
            &mut mt,
        )
        .unwrap();
        // No coercion (match_field is not "source_type"), validation passed.
        assert_eq!(mt, "exact");
    }

    // ------------------------------------------------------------------
    // NAN-689: TOML / VRL injection via connection_config and routing_rule
    // values. The structured-emission generators must round-trip a malicious
    // payload as a single string scalar — no extra TOML tables, no extra
    // VRL string boundaries crossed.
    // ------------------------------------------------------------------

    /// Recursively check the parsed TOML for a top-level `transforms` or
    /// `sinks` table — these are the keys an attacker would target to land
    /// arbitrary VRL or to redirect logs. The intended source-block output
    /// only has `sources`. Substring matching against the raw text is too
    /// coarse: a malicious payload survives as *escaped content* of a
    /// `"""…"""` string literal and produces literal `[transforms.evil]`
    /// substrings that are not actual TOML tables.
    fn parsed_has_unexpected_top_level_tables(parsed: &toml::Value) -> bool {
        let table = match parsed.as_table() {
            Some(t) => t,
            None => return true,
        };
        for (k, _) in table.iter() {
            if k != "sources" {
                return true;
            }
        }
        false
    }

    /// Kafka generator must escape a `bootstrap_servers` value that tries
    /// to terminate the TOML string and inject a `[transforms.evil]` block.
    /// After the fix the generated TOML parses cleanly as a single source —
    /// no extra tables — and the malicious string survives as content.
    #[test]
    fn kafka_generator_neutralises_bootstrap_servers_toml_injection() {
        let payload = "bs:9092\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "bootstrap_servers": payload, "topics": ["logs"] });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
        let parsed: toml::Value = toml::from_str(&out).expect("generated TOML must parse");
        assert!(
            !parsed_has_unexpected_top_level_tables(&parsed),
            "expected only [sources.<name>] tables; injection produced extras:\n{out}",
        );
        assert_eq!(
            parsed["sources"]["test"]["bootstrap_servers"].as_str().unwrap(),
            payload,
            "bootstrap_servers value must round-trip verbatim",
        );
    }

    /// AWS S3 generator: malicious region must not break out into new tables.
    #[test]
    fn aws_s3_generator_neutralises_region_toml_injection() {
        let payload = "us-east-1\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({
            "region": payload,
            "sqs_queue_url": "https://sqs.example/q",
        });
        let out = SourceConfigService::generate_aws_s3_source("test", &conn, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["region"].as_str().unwrap(),
            payload,
        );
    }

    /// GCP Pub/Sub generator: malicious project value cannot inject tables.
    #[test]
    fn gcp_pubsub_generator_neutralises_project_toml_injection() {
        let payload = "proj\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "project": payload, "subscription": "sub" });
        let out = SourceConfigService::generate_gcp_pubsub_source("test", &conn, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["project"].as_str().unwrap(),
            payload,
        );
    }

    /// Kafka credentials path: a SASL `password` containing a TOML breakout
    /// shouldn't escape the `[sources.test.sasl]` block.
    #[test]
    fn kafka_generator_neutralises_sasl_password_toml_injection() {
        let payload = "p\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "bootstrap_servers": "host:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "PLAIN",
            "sasl_username": "u",
            "sasl_password": payload,
        });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["sasl"]["password"].as_str().unwrap(),
            payload,
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-1 / K-2: TLS block + librdkafka security.protocol must
    // both make it into the generated Vector source so cloud-hosted
    // brokers (Confluent Cloud, MSK, Aiven) actually connect instead of
    // failing silently with a PLAINTEXT handshake against a TLS broker.
    // ------------------------------------------------------------------

    /// Credential with `tls_enabled = true` and a CA cert path persisted by
    /// the caller must emit `[sources.<name>.tls]` with `enabled = true` and
    /// the supplied `ca_file`.
    #[test]
    fn kafka_generator_emits_tls_block_when_credential_has_tls() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker.confluent.cloud:9092",
            "topics": ["audit"],
        });
        let creds = serde_json::json!({
            "sasl_mechanism": "SCRAM-SHA-512",
            "sasl_username": "u",
            "sasl_password": "p",
            "tls_enabled": true,
            "tls_ca_cert": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        });
        let ca_path = "/etc/vector/source-creds/kafka_test.ca.pem";
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::nil(),
            &conn,
            Some(&creds),
            Some(ca_path),
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let tls = parsed["sources"]["test"]["tls"]
            .as_table()
            .expect("tls block must be emitted when tls_enabled");
        assert_eq!(tls["enabled"].as_bool(), Some(true));
        assert_eq!(tls["ca_file"].as_str(), Some(ca_path));
    }

    /// `tls_enabled = true` without a custom CA still emits the TLS block —
    /// Vector then trusts the system CA bundle (Confluent Cloud's public CA
    /// is in there). No `ca_file` key should appear.
    #[test]
    fn kafka_generator_tls_block_omits_ca_file_when_no_cert_supplied() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker:9092",
            "topics": ["x"],
        });
        let creds = serde_json::json!({ "tls_enabled": true });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let tls = parsed["sources"]["test"]["tls"]
            .as_table()
            .expect("tls block must be emitted");
        assert_eq!(tls["enabled"].as_bool(), Some(true));
        assert!(
            !tls.contains_key("ca_file"),
            "ca_file must be absent when no cert is provided, fall back to system CAs",
        );
    }

    /// SASL + TLS together must produce `security.protocol = "SASL_SSL"`.
    #[test]
    fn kafka_generator_emits_security_protocol_sasl_ssl() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "SCRAM-SHA-256",
            "sasl_username": "u",
            "sasl_password": "p",
            "tls_enabled": true,
        });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SASL_SSL"),
        );
    }

    /// SASL only (no TLS) → SASL_PLAINTEXT. Covers the local SASL_PLAINTEXT
    /// listener case in the test stand.
    #[test]
    fn kafka_generator_emits_security_protocol_sasl_plaintext() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "PLAIN",
            "sasl_username": "u",
            "sasl_password": "p",
        });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SASL_PLAINTEXT"),
        );
    }

    /// TLS only (no SASL) → SSL. Used by anonymous-but-TLS-required brokers.
    #[test]
    fn kafka_generator_emits_security_protocol_ssl_when_tls_only() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9093", "topics": ["x"] });
        let creds = serde_json::json!({ "tls_enabled": true });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SSL"),
        );
    }

    /// Plain anonymous broker (T-1 local stand): no librdkafka_options table
    /// should appear — keeping the generated TOML minimal and letting Vector
    /// use its PLAINTEXT default.
    #[test]
    fn kafka_generator_omits_security_protocol_when_plaintext() {
        let conn = serde_json::json!({ "bootstrap_servers": "kafka:9092", "topics": ["x"] });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(
            parsed["sources"]["test"].get("librdkafka_options").is_none(),
            "anonymous PLAINTEXT must not emit librdkafka_options:\n{out}",
        );
        assert!(
            parsed["sources"]["test"].get("tls").is_none(),
            "anonymous PLAINTEXT must not emit tls block:\n{out}",
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-3: consumer-group_id must be unique per source-config when
    // not explicitly set. Two implicit-group_id Kafka configs against the
    // same broker previously shared the literal "nanosiem" group and split
    // partitions across them, silently halving throughput per consumer.
    // ------------------------------------------------------------------

    /// Two different source-config ids without explicit `group_id` must
    /// produce two different generated group_ids. Format is documented as
    /// `nanosiem-<base32 typeid suffix>` so operators recognize it on the
    /// broker side.
    #[test]
    fn kafka_generator_auto_generates_unique_group_id_per_config() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        let out_a =
            SourceConfigService::generate_kafka_source("a", &id_a, &conn, None, None);
        let out_b =
            SourceConfigService::generate_kafka_source("b", &id_b, &conn, None, None);

        let parsed_a: toml::Value = toml::from_str(&out_a).expect("a must parse");
        let parsed_b: toml::Value = toml::from_str(&out_b).expect("b must parse");

        let gid_a = parsed_a["sources"]["a"]["group_id"]
            .as_str()
            .expect("group_id must be emitted");
        let gid_b = parsed_b["sources"]["b"]["group_id"]
            .as_str()
            .expect("group_id must be emitted");

        assert_ne!(gid_a, gid_b, "two configs must get different group_ids");
        assert!(
            gid_a.starts_with("nanosiem-"),
            "auto-generated group_id must use the nanosiem- prefix, got {gid_a}",
        );
        assert_eq!(
            gid_a.len(),
            "nanosiem-".len() + 26,
            "auto-generated suffix must be a 26-char base32 typeid suffix, got {gid_a}",
        );
    }

    /// Explicit user-set `group_id` in `connection_config` always wins —
    /// even when the user picks the legacy literal "nanosiem", we must
    /// keep that value (this is the post-migration shape for already-
    /// deployed configs and preserves their committed broker offsets).
    #[test]
    fn kafka_generator_preserves_explicit_group_id() {
        let conn = serde_json::json!({
            "bootstrap_servers": "h:9092",
            "topics": ["x"],
            "group_id": "my-team-pipeline",
        });
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::new_v4(),
            &conn,
            None,
            None,
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["group_id"].as_str(),
            Some("my-team-pipeline"),
        );
    }

    /// Post-migration shape: existing rows backfilled to `"nanosiem"` by
    /// `190_kafka_default_group_id_backfill.sql` must keep that value so
    /// already-deployed consumers don't restart from `auto_offset_reset`.
    #[test]
    fn kafka_generator_preserves_backfilled_nanosiem_group_id() {
        let conn = serde_json::json!({
            "bootstrap_servers": "h:9092",
            "topics": ["x"],
            "group_id": "nanosiem",
        });
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::new_v4(),
            &conn,
            None,
            None,
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(parsed["sources"]["test"]["group_id"].as_str(), Some("nanosiem"));
    }

    // ------------------------------------------------------------------
    // NAN-884 K-6: per-config routing transform must stamp
    // `.metadata.forwarded_via` for pull sources so downstream rows can
    // be filtered by ingestion path (NAN-201 covered HTTP / HEC / vector
    // already via the always-on transforms in config/vector/*.toml).
    // ------------------------------------------------------------------

    /// Kafka routing transform must set `.metadata.forwarded_via = "kafka"`
    /// before the source_type rules so detection rules / ad-hoc searches can
    /// filter by ingestion path the same way they do for HEC.
    #[test]
    fn routing_transform_stamps_forwarded_via_for_kafka() {
        let config = make_config(
            "kafka",
            vec![make_rule(1000, "topic", "default", None, "apache_http_server")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"kafka\""),
            "expected kafka forwarded_via stamp, got:\n{vrl}",
        );
        assert!(
            vrl.contains("if !is_object(.metadata)"),
            "expected metadata object guard, got:\n{vrl}",
        );
    }

    /// AWS S3 routing transform stamps `aws_s3` (same gap as Kafka — pull
    /// source with no upstream `forwarded_via`).
    #[test]
    fn routing_transform_stamps_forwarded_via_for_aws_s3() {
        let config = make_config(
            "aws_s3",
            vec![make_rule(1000, "source_type", "default", None, "aws_cloudtrail")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"aws_s3\""),
            "expected aws_s3 forwarded_via stamp, got:\n{vrl}",
        );
    }

    /// GCP Pub/Sub routing transform stamps `gcp_pubsub`.
    #[test]
    fn routing_transform_stamps_forwarded_via_for_gcp_pubsub() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(1000, "source_type", "default", None, "gcp_audit_log")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"gcp_pubsub\""),
            "expected gcp_pubsub forwarded_via stamp, got:\n{vrl}",
        );
    }

    /// System-level sources (http / vector / splunk_hec) MUST NOT get the
    /// per-config stamp — their always-on transforms in `config/vector/*.toml`
    /// already set `forwarded_via`, and a second assignment here would
    /// clobber the upstream value (e.g. overwrite `splunk_hec` with `http`).
    #[test]
    fn routing_transform_skips_forwarded_via_for_system_level_sources() {
        let config = make_config(
            "http",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("aws_cloudtrail_raw"),
                "aws_cloudtrail",
            )],
        );

        let toml_out = SourceConfigService::generate_routing_transform(
            &config,
            "source_type_extract",
            "route",
            true,
        );
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            !vrl.contains("forwarded_via"),
            "system-level routing transform must not stamp forwarded_via, got:\n{vrl}",
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-7: Kafka header match must wrap value access in
    // `to_string(...) ?? ""`. Without the coercion the comparison is
    // `Bytes == String` and is always-false; the entire "Header
    // (recommended)" routing preset was broken since it shipped.
    // ------------------------------------------------------------------

    /// `prefix` / `suffix` / `contains` match types all take string-coerced
    /// inputs too — coercion must apply to every match type, not just
    /// `exact`.
    #[test]
    fn kafka_headers_path_match_field_is_coerced_for_all_match_types() {
        for (mt, expected_fn_call) in [
            ("prefix", "starts_with((to_string(.headers.team) ?? \"\")"),
            ("suffix", "ends_with((to_string(.headers.team) ?? \"\")"),
            ("contains", "contains((to_string(.headers.team) ?? \"\")"),
            ("regex", "match((to_string(.headers.team) ?? \"\")"),
        ] {
            let config = make_config(
                "kafka",
                vec![
                    make_rule(10, "headers.team", mt, Some("audit"), "audit_logs"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            );
            let vrl =
                SourceConfigService::generate_routing_transform(&config, "src", "route", false);
            assert!(
                vrl.contains(expected_fn_call),
                "match_type={mt} must coerce header to string, got:\n{vrl}",
            );
        }
    }

    /// Non-Kafka configs do not need (and must not get) the header
    /// coercion — `gcp_pubsub` already exposes `.attributes` as
    /// `Object(String, String)`, and adding a `to_string(...) ?? ""`
    /// wrapper there would be dead weight.
    #[test]
    fn non_kafka_header_paths_are_not_coerced() {
        // gcp_pubsub commonly uses `attributes.*`; even if a rule used the
        // word "headers" the source type isn't kafka so no coercion.
        let config = make_config(
            "gcp_pubsub",
            vec![
                make_rule(
                    10,
                    "attributes.source_type",
                    "exact",
                    Some("limacharlie_edr"),
                    "limacharlie_edr",
                ),
                make_rule(1000, "subscription", "default", None, "unknown"),
            ],
        );
        let vrl =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        assert!(
            vrl.contains("if .attributes.source_type == \"limacharlie_edr\""),
            "gcp_pubsub attributes must keep plain access, got:\n{vrl}",
        );
        assert!(
            !vrl.contains("to_string(.attributes"),
            "gcp_pubsub attributes must NOT be wrapped, got:\n{vrl}",
        );
    }

    /// Coerced VRL must still compile against the standard VRL function
    /// set — otherwise Vector rejects the generated config on deploy and
    /// the failure surfaces only in saturn logs (per
    /// `feedback_compile_test_generated_vrl`).
    #[test]
    fn routing_transform_vrl_compiles_with_kafka_header_coercion() {
        let fns = vrl::stdlib::all();
        for mt in ["exact", "prefix", "suffix", "contains", "regex"] {
            let config = make_config(
                "kafka",
                vec![
                    make_rule(10, "headers.source_type", mt, Some("sysmon"), "sysmon"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            );
            let toml_out = SourceConfigService::generate_routing_transform(
                &config, "src", "route", false,
            );
            let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
            let vrl_src = parsed["transforms"]["route"]["source"]
                .as_str()
                .expect("source string");
            if let Err(diagnostics) = vrl::compiler::compile(vrl_src, &fns) {
                let formatted =
                    vrl::diagnostic::Formatter::new(vrl_src, diagnostics).to_string();
                panic!(
                    "match_type={mt} kafka header VRL failed to compile:\n\
                     {vrl_src}\n\
                     ---\n{formatted}",
                );
            }
        }
    }

    /// Unit-level coverage for the helper itself — Kafka headers get
    /// coerced, everything else stays plain.
    #[test]
    fn routing_field_expression_picks_coerced_form_for_kafka_headers_only() {
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "headers.source_type"),
            "(to_string(.headers.source_type) ?? \"\")",
        );
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "headers.team_id"),
            "(to_string(.headers.team_id) ?? \"\")",
        );
        // Kafka non-headers fields stay plain.
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "topic"),
            ".topic",
        );
        // Other config types stay plain even for `headers.*` (defensive).
        assert_eq!(
            SourceConfigService::routing_field_expression("gcp_pubsub", "attributes.source_type"),
            ".attributes.source_type",
        );
        assert_eq!(
            SourceConfigService::routing_field_expression("aws_s3", "bucket"),
            ".bucket",
        );
    }

    /// VRL compile gate (per `feedback_compile_test_generated_vrl`): the
    /// emitted metadata-object guard + forwarded_via assignment must
    /// type-check against the standard VRL function set — otherwise Vector
    /// startup fails on deploy and the failure surfaces only in saturn
    /// logs (NAN-667 E651 precedent).
    #[test]
    fn routing_transform_vrl_compiles_with_forwarded_via_stamp() {
        let fns = vrl::stdlib::all();
        for config_type in ["kafka", "aws_s3", "gcp_pubsub"] {
            let config = make_config(
                config_type,
                vec![make_rule(1000, "topic", "default", None, "apache_http_server")],
            );
            let toml_out = SourceConfigService::generate_routing_transform(
                &config, "src", "route", false,
            );
            let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
            let vrl_src = parsed["transforms"]["route"]["source"]
                .as_str()
                .expect("source string");
            if let Err(diagnostics) = vrl::compiler::compile(vrl_src, &fns) {
                let formatted =
                    vrl::diagnostic::Formatter::new(vrl_src, diagnostics).to_string();
                panic!(
                    "routing transform VRL for {config_type} failed to compile:\n\
                     {vrl_src}\n\
                     ---\n{formatted}",
                );
            }
        }
    }

    /// Routing transform: a `target_source_type` containing `'''` would have
    /// closed the old triple-single-quoted TOML literal. With `toml::Value::String`
    /// emission it survives as escaped content.
    #[test]
    fn routing_transform_neutralises_target_triple_quote_injection() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(
                    10,
                    "topic",
                    "exact",
                    Some("audit"),
                    "ok'''\n[transforms.evil]\nx = '''",
                ),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        // The only transform table should be the route we generated
        let transforms = parsed.get("transforms").and_then(|t| t.as_table()).unwrap();
        assert_eq!(
            transforms.len(),
            1,
            "expected exactly one transform; injection produced extras:\n{out}",
        );
        assert!(transforms.contains_key("route"));
    }

    /// VRL escape: a `match_value` containing `"` would end the VRL string
    /// without escaping; check the embedded VRL has the escaped form.
    #[test]
    fn routing_transform_escapes_match_value_quote() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "exact", Some("a\"b"), "ok"),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let source = parsed["transforms"]["route"]["source"].as_str().unwrap();
        // VRL must see the escaped quote, not a bare one
        assert!(
            source.contains("\"a\\\"b\""),
            "expected escaped quote inside VRL string, got:\n{source}",
        );
    }

    /// Regex-typed rule with a `'` in the pattern would close the VRL raw
    /// string `r'…'`. Generator must skip+warn rather than emit broken VRL.
    #[test]
    fn routing_transform_skips_regex_with_single_quote() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "regex", Some("foo'bar"), "ok"),
                make_rule(1000, "topic", "default", None, "fallback"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let source = parsed["transforms"]["route"]["source"].as_str().unwrap();
        // Skipped — the if-block isn't emitted; only the default assignment
        assert!(
            !source.contains("match("),
            "skipped regex rule still appeared in VRL:\n{source}",
        );
        assert!(source.contains(".source_type = \"fallback\""));
    }

    // ------------------------------------------------------------------
    // NAN-689: connection_config validation at create/update.
    // ------------------------------------------------------------------

    #[test]
    fn validate_connection_config_rejects_newline_in_string_scalar() {
        let conn = serde_json::json!({
            "bootstrap_servers": "host:9092\n[transforms.evil]"
        });
        let err = SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
        assert!(
            err.to_string().contains("control character"),
            "expected control-char error, got: {err}",
        );
    }

    #[test]
    fn validate_connection_config_rejects_carriage_return() {
        let conn = serde_json::json!({ "address": "0.0.0.0:8088\r" });
        SourceConfigService::validate_connection_config("splunk_hec", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_nul_byte() {
        let conn = serde_json::json!({ "project": "proj\0name" });
        SourceConfigService::validate_connection_config("gcp_pubsub", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_control_char_in_array_element() {
        let conn = serde_json::json!({
            "topics": ["normal", "bad\ntopic"]
        });
        let err = SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
        assert!(
            err.to_string().contains("topics[1]"),
            "expected path-aware error, got: {err}",
        );
    }

    #[test]
    fn validate_connection_config_allows_legitimate_payload() {
        // Quotes and backslashes are fine — the toml crate escapes them on
        // emission, and rejecting them would block valid URLs / SASL passwords.
        let kafka = serde_json::json!({
            "bootstrap_servers": "broker-1.example.com:9092,broker-2.example.com:9092",
            "topics": ["audit-logs", "app-events"],
            "group_id": "nanosiem",
            "auto_offset_reset": "latest",
        });
        SourceConfigService::validate_connection_config("kafka", &kafka).unwrap();

        let s3 = serde_json::json!({
            "sqs_queue_url": "https://sqs.us-east-1.amazonaws.com/123/q",
            "region": "us-east-1",
            "compression": "gzip",
        });
        SourceConfigService::validate_connection_config("aws_s3", &s3).unwrap();

        let gcp = serde_json::json!({
            "project": "my-gcp-proj",
            "subscription": "projects/my-gcp-proj/subscriptions/my-sub",
            "ack_deadline_secs": 600,
        });
        SourceConfigService::validate_connection_config("gcp_pubsub", &gcp).unwrap();

        // NAN-855: post-NAN-853, HEC's connection_config is non-configurable
        // per source. Empty payloads are the valid shape; the next test below
        // (`validate_connection_config_rejects_vestigial_splunk_hec_fields`)
        // pins the rejection of populated `address` / `valid_tokens`.
        let hec_empty = serde_json::json!({});
        SourceConfigService::validate_connection_config("splunk_hec", &hec_empty).unwrap();
        let hec_nulls = serde_json::json!({
            "address": null,
            "valid_tokens": [],
            "permit_origin": [],
            "tls": {},
        });
        SourceConfigService::validate_connection_config("splunk_hec", &hec_nulls).unwrap();
    }

    /// NAN-883: lock the single-instance driver matrix. `splunk_hec` is the
    /// only driver where the OOTB listener is shared and a second user
    /// config would emit a colliding routing transform. Push drivers
    /// (http/vector) and broker pulls (kafka/aws_s3/gcp_pubsub) all support
    /// multiple instances.
    #[test]
    fn is_single_instance_driver_matrix() {
        assert!(SourceConfigService::is_single_instance_driver("splunk_hec"));
        for driver in ["http", "vector", "kafka", "aws_s3", "gcp_pubsub", "unknown"] {
            assert!(
                !SourceConfigService::is_single_instance_driver(driver),
                "{driver} must not be single-instance",
            );
        }
    }

    /// NAN-883: `reject_if_duplicate_single_instance` is the pure decision
    /// the create-path uses against the existing-configs list returned by
    /// the repository. The DB-level partial unique index (migration 184)
    /// is the race-safety backstop; this is the friendly-error path.
    #[test]
    fn reject_if_duplicate_single_instance_returns_conflict_on_match() {
        let existing = vec![
            fake_config("kafka-prod", "kafka"),
            fake_config("hec-main", "splunk_hec"),
        ];
        // Existing splunk_hec → duplicate creation must be rejected.
        let err =
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &existing)
                .expect("expected Conflict, got None");
        match err {
            SourceConfigServiceError::Conflict(msg) => {
                assert!(msg.contains("splunk_hec"), "msg: {msg}");
                assert!(msg.contains("Only one"), "msg: {msg}");
            }
            other => panic!("expected Conflict variant, got {other:?}"),
        }
    }

    #[test]
    fn reject_if_duplicate_single_instance_passes_with_no_existing_hec() {
        // No HEC in the list — even with other drivers present, creating a
        // HEC config must be allowed.
        let existing = vec![
            fake_config("kafka-prod", "kafka"),
            fake_config("s3-cloudtrail", "aws_s3"),
        ];
        assert!(
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &existing)
                .is_none()
        );
    }

    #[test]
    fn reject_if_duplicate_single_instance_passes_with_empty_existing() {
        assert!(
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &[]).is_none()
        );
    }

    /// Helper: build a minimal SourceConfiguration row for in-memory tests.
    fn fake_config(name: &str, config_type: &str) -> SourceConfiguration {
        SourceConfiguration {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            config_type: config_type.to_string(),
            connection_config: serde_json::json!({}),
            credential_id: None,
            enabled: false,
            deployed: false,
            deployed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
        }
    }

    /// NAN-855: vestigial `splunk_hec` fields (`address`, `valid_tokens`,
    /// `permit_origin`, `tls`) must be rejected when populated — they have
    /// zero effect at deploy time post-NAN-853, so accepting them would
    /// silently mislead operators into thinking they're configurable.
    #[test]
    fn validate_connection_config_rejects_vestigial_splunk_hec_fields() {
        for (field, payload) in [
            (
                "address",
                serde_json::json!({ "address": "0.0.0.0:8088" }),
            ),
            (
                "valid_tokens",
                serde_json::json!({
                    "valid_tokens": ["00000000-0000-0000-0000-000000000000"]
                }),
            ),
            (
                "permit_origin",
                serde_json::json!({ "permit_origin": ["10.0.0.0/8"] }),
            ),
            (
                "tls",
                serde_json::json!({ "tls": { "enabled": true } }),
            ),
        ] {
            let err = SourceConfigService::validate_connection_config("splunk_hec", &payload)
                .unwrap_err();
            assert!(
                err.to_string().contains(field) && err.to_string().contains("not configurable"),
                "expected rejection of vestigial `{field}`, got: {err}",
            );
        }
    }

    #[test]
    fn validate_connection_config_allows_quotes_and_backslashes() {
        // toml::Value::String handles escaping, so these pass through unharmed.
        let conn = serde_json::json!({
            "bootstrap_servers": "host:9092",
            "topics": ["with\"quote", "with\\backslash"]
        });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_kafka_topics_wrong_type() {
        // topics must be an array, not an object/string.
        let conn = serde_json::json!({ "topics": "not-an-array" });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();

        let conn = serde_json::json!({ "topics": [42] });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_known_field_wrong_type() {
        let conn = serde_json::json!({ "bootstrap_servers": ["should", "be", "string"] });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();

        let conn = serde_json::json!({ "address": 8088 });
        SourceConfigService::validate_connection_config("splunk_hec", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_allows_unknown_driver() {
        // System-level (`http`, `vector`) and unknown drivers skip
        // structural checks but still get the char-safety pass.
        let conn = serde_json::json!({ "anything": "fine" });
        SourceConfigService::validate_connection_config("http", &conn).unwrap();
        SourceConfigService::validate_connection_config("vector", &conn).unwrap();
        SourceConfigService::validate_connection_config("unknown_driver", &conn).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_root_array() {
        let conn = serde_json::json!(["nope"]);
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_allows_null_root() {
        // Some legacy rows have null connection_config; generators tolerate
        // it via `.as_str().unwrap_or(...)` defaults.
        SourceConfigService::validate_connection_config("kafka", &serde_json::Value::Null).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_control_char_in_object_key() {
        let mut map = serde_json::Map::new();
        map.insert("bad\nkey".to_string(), serde_json::Value::String("v".into()));
        SourceConfigService::validate_connection_config("kafka", &serde_json::Value::Object(map))
            .unwrap_err();
    }

    // ------------------------------------------------------------------
    // NAN-689 P0: name validation. The leading TOML comment of the
    // generated config interpolates `config.name` raw — a `\n` in name
    // would close the comment and let the rest be parsed as TOML
    // structure, bypassing the structured-emission defense.
    // ------------------------------------------------------------------

    #[test]
    fn validate_name_rejects_newline() {
        SourceConfigService::validate_name("foo\n[transforms.evil]").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_carriage_return() {
        SourceConfigService::validate_name("foo\r").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_nul() {
        SourceConfigService::validate_name("foo\0bar").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_other_control_chars() {
        SourceConfigService::validate_name("foo\x07bell").unwrap_err();
        SourceConfigService::validate_name("foo\x1bescape").unwrap_err();
        SourceConfigService::validate_name("foo\x7fdel").unwrap_err();
    }

    #[test]
    fn validate_name_allows_tab() {
        // Tab is allowed — same policy as connection_config strings.
        SourceConfigService::validate_name("foo\tbar").unwrap();
    }

    #[test]
    fn validate_name_allows_unicode_and_punctuation() {
        // Names are user-display strings; they go through `safe_name` for
        // file paths and identifiers, so the only restriction here is on
        // characters that would break the TOML comment they land in.
        SourceConfigService::validate_name("My Source [prod] (us-east-1)").unwrap();
        SourceConfigService::validate_name("источник").unwrap();
    }

    #[test]
    fn validate_name_rejects_empty() {
        SourceConfigService::validate_name("").unwrap_err();
    }

    // ------------------------------------------------------------------
    // NAN-689 P2: routing-rule write-time validation for match_value /
    // target_source_type. The generator's vrl_escape covers `\` and `"`,
    // these checks cover the cases it can't (control chars + regex `'`).
    // ------------------------------------------------------------------

    /// NAN-858: target_source_type must conform to the same allow-list the
    /// rollup IN-clause sanitizer uses. Reject the `${source_type}` sentinel
    /// at write time so it never gets persisted (and the WARN it caused on
    /// every `GET /api/source-configurations` stays gone).
    #[test]
    fn validate_routing_rule_values_rejects_passthrough_sentinel_target() {
        let err = SourceConfigService::validate_routing_rule_values(
            "default",
            None,
            "${source_type}",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("target_source_type"),
            "expected target_source_type error, got: {err}"
        );
    }

    #[test]
    fn validate_routing_rule_values_rejects_empty_target() {
        let err =
            SourceConfigService::validate_routing_rule_values("default", None, "").unwrap_err();
        assert!(err.to_string().contains("target_source_type"));
    }

    #[test]
    fn validate_routing_rule_values_rejects_dot_in_target() {
        let err = SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("v"),
            "some.dotted.value",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_source_type"));
    }

    /// Counterpart: typical valid values still pass.
    #[test]
    fn validate_routing_rule_values_accepts_safe_targets() {
        for target in ["apache_access", "aws-cloudtrail", "Sysmon", "unknown", "x"] {
            SourceConfigService::validate_routing_rule_values("default", None, target)
                .unwrap_or_else(|e| {
                    panic!("expected {target:?} to be accepted, got error: {e}")
                });
        }
    }

    #[test]
    fn validate_routing_rule_values_rejects_newline_in_match_value() {
        let err = SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("audit\nlogs"),
            "ok",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("match_value"),
            "expected match_value error, got: {err}",
        );
    }

    #[test]
    fn validate_routing_rule_values_rejects_newline_in_target() {
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("audit"),
            "aws_cloudtrail\n",
        )
        .unwrap_err();
    }

    #[test]
    fn validate_routing_rule_values_rejects_single_quote_in_regex() {
        let err = SourceConfigService::validate_routing_rule_values(
            "regex",
            Some("foo'bar"),
            "ok",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("single quote"),
            "expected explicit single-quote error, got: {err}",
        );
    }

    #[test]
    fn validate_routing_rule_values_allows_single_quote_in_non_regex() {
        // Non-regex match types interpolate into `"…"` strings via
        // vrl_escape; single quotes are fine there.
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("foo'bar"),
            "ok",
        )
        .unwrap();
    }

    #[test]
    fn validate_routing_rule_values_allows_quotes_and_backslashes_in_match_value() {
        // match_value gets vrl_escape'd before interpolation, so quotes and
        // backslashes are legitimate (e.g. matching a command_line substring
        // that contains them). target_source_type is *not* a free-form string
        // though — NAN-858 restricts it to [A-Za-z0-9_-] so the rollup IN
        // clause stays clean.
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("a\"b\\c"),
            "safe_target",
        )
        .unwrap();
    }

    #[test]
    fn validate_routing_rule_values_allows_default_with_no_match_value() {
        SourceConfigService::validate_routing_rule_values("default", None, "unknown").unwrap();
    }

    // ------------------------------------------------------------------
    // NAN-689 acceptance criterion #3: validate_generated_config gate.
    // ------------------------------------------------------------------

    /// A well-formed kafka source-block + routing transform passes both
    /// TOML parse and VRL compile checks.
    #[test]
    fn validate_generated_config_accepts_well_formed_kafka_pipeline() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker:9092",
            "topics": ["audit-logs"],
            "group_id": "nanosiem",
            "auto_offset_reset": "latest",
        });
        let mut full = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
        full.push('\n');
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "kafka",
                vec![
                    make_rule(10, "topic", "exact", Some("audit-logs"), "aws_cloudtrail"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            ),
            "test_source",
            "test_route",
            false,
        );
        full.push_str(&routing);

        SourceConfigService::validate_generated_config(&full)
            .expect("clean kafka pipeline must pass validation");
    }

    /// Routing transform on its own (the system-level / rewrite-rules path)
    /// also passes the gate.
    #[test]
    fn validate_generated_config_accepts_routing_transform_only() {
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "http",
                vec![make_rule(
                    10,
                    "source_type",
                    "exact",
                    Some("aws_cloudtrail_raw"),
                    "aws_cloudtrail",
                )],
            ),
            "source_type_extract",
            "test_route",
            true,
        );
        SourceConfigService::validate_generated_config(&routing)
            .expect("clean routing transform must pass validation");
    }

    /// Even the empty default-only case is valid VRL.
    #[test]
    fn validate_generated_config_accepts_default_only_routing_transform() {
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "kafka",
                vec![make_rule(1000, "topic", "default", None, "unknown")],
            ),
            "src",
            "route",
            false,
        );
        SourceConfigService::validate_generated_config(&routing)
            .expect("default-only routing must pass validation");
    }

    /// Malformed TOML (e.g. unterminated string) is rejected by the
    /// TOML-parse layer.
    #[test]
    fn validate_generated_config_rejects_malformed_toml() {
        let bad = "[sources.test]\ntype = \"kafka\nbootstrap_servers = \"x\"\n";
        let err = SourceConfigService::validate_generated_config(bad).unwrap_err();
        assert!(
            err.to_string().contains("not valid TOML"),
            "expected TOML-parse error, got: {err}",
        );
    }

    /// Malformed VRL inside a remap transform's `source` is rejected by
    /// the VRL-compile layer.
    #[test]
    fn validate_generated_config_rejects_malformed_vrl_in_remap() {
        let bad = "[transforms.bad]\n\
                   type = \"remap\"\n\
                   inputs = [\"src\"]\n\
                   source = \"this is :: not :: valid :: vrl\"\n";
        let err = SourceConfigService::validate_generated_config(bad).unwrap_err();
        assert!(
            err.to_string().contains("failed to compile"),
            "expected VRL-compile error, got: {err}",
        );
        assert!(
            err.to_string().contains("'bad'"),
            "expected transform name in error, got: {err}",
        );
    }

    /// Non-`remap` transforms (e.g. `route`, `filter`) skip the VRL
    /// compile step — they don't carry user-controlled VRL.
    #[test]
    fn validate_generated_config_skips_non_remap_transforms() {
        // A `route` transform with a `source` field that isn't VRL would
        // otherwise trip the compile check; gate skips it because type != "remap".
        let toml = "[transforms.r]\n\
                    type = \"route\"\n\
                    inputs = [\"src\"]\n\
                    source = \"not vrl, ignored\"\n\
                    [transforms.r.route]\n\
                    a = '.foo == \"x\"'\n";
        SourceConfigService::validate_generated_config(toml)
            .expect("non-remap transforms must skip VRL compile");
    }

    #[test]
    fn normalize_pubsub_subscription_strips_full_resource_path() {
        // Vector double-prefixes if we hand it the full resource name.
        let bare = normalize_pubsub_subscription(
            "projects/nano-rs/subscriptions/nanosiem-limacharlie-sub",
        );
        assert_eq!(bare, "nanosiem-limacharlie-sub");
    }

    #[test]
    fn normalize_pubsub_subscription_passes_bare_name_through() {
        let bare =
            normalize_pubsub_subscription("nanosiem-limacharlie-sub");
        assert_eq!(bare, "nanosiem-limacharlie-sub");
    }

    #[test]
    fn normalize_pubsub_subscription_handles_trailing_slash() {
        let bare = normalize_pubsub_subscription(
            "projects/nano-rs/subscriptions/foo/",
        );
        assert_eq!(bare, "foo");
    }

    #[test]
    fn normalize_pubsub_subscription_handles_empty() {
        assert_eq!(normalize_pubsub_subscription(""), "");
    }

    // Snapshot redaction itself lives in `parsers::vector_config::redaction`
    // and is unit-tested there. The wiring assertion that the source-config
    // deploy path actually invokes it is best validated end-to-end against a
    // real database (out of scope for this unit module).

    fn bare_config(name: &str, config_type: &str) -> SourceConfiguration {
        let now = Utc::now();
        SourceConfiguration {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            config_type: config_type.to_string(),
            connection_config: serde_json::json!({}),
            credential_id: None,
            enabled: true,
            deployed: true,
            deployed_at: Some(now),
            created_at: now,
            updated_at: now,
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
        }
    }

    /// Guards against the NAN-852 regression: when the base config defines
    /// `hec_normalize` (OOTB open-core), any source-config mutation rebuilds
    /// the router inputs and `hec_normalize` must never be dropped.
    #[test]
    fn compute_router_inputs_always_contains_hec_normalize_when_present() {
        let scenarios: Vec<Vec<SourceConfiguration>> = vec![
            vec![],
            vec![bare_config("kafka_audit", "kafka")],
            vec![bare_config("http_main", "http")],
            vec![bare_config("vec_relay", "vector"), bare_config("s3_logs", "s3")],
        ];

        for configs in scenarios {
            let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
            assert!(
                inputs.iter().any(|s| s == "hec_normalize"),
                "hec_normalize missing from inputs for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            assert!(
                inputs.iter().any(|s| s == "vector_merge"),
                "vector_merge missing from inputs for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    /// NAN-867: when the base config doesn't define `hec_normalize` (nano-main
    /// customer deploys), it must never appear in router inputs — Vector 0.55
    /// rejects dangling input references at startup.
    #[test]
    fn compute_router_inputs_never_contains_hec_normalize_when_absent() {
        let scenarios: Vec<Vec<SourceConfiguration>> = vec![
            vec![],
            vec![bare_config("kafka_audit", "kafka")],
            vec![bare_config("http_main", "http")],
            vec![bare_config("vec_relay", "vector"), bare_config("s3_logs", "s3")],
        ];

        for configs in scenarios {
            let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, false);
            assert!(
                !inputs.iter().any(|s| s == "hec_normalize"),
                "hec_normalize emitted with hec_normalize_present=false for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn compute_router_inputs_appends_non_system_routes_after_base() {
        let configs = vec![bare_config("kafka_audit", "kafka")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert_eq!(
            inputs,
            vec![
                "source_type_extract",
                "vector_merge",
                "hec_normalize",
                "otlp_logs_prep",
                "kafka_audit_route"
            ]
        );
    }

    #[test]
    fn compute_router_inputs_drops_source_type_extract_when_system_route_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["vector_merge", "hec_normalize", "otlp_logs_prep", "http_main_route"]
        );
    }

    #[test]
    fn compute_router_inputs_skips_system_route_when_no_file_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "hec_normalize", "otlp_logs_prep"]
        );
    }

    /// NAN-1442 (Saturn 2× ingestion): `http` and `vector` configs BOTH
    /// intermediate `source_type_extract`. Deploying both must wire exactly
    /// ONE route into `source_router`, or the post-extract stream reaches it
    /// twice and every event is inserted into ClickHouse twice.
    #[test]
    fn compute_router_inputs_dedupes_http_and_vector_sharing_source_type_extract() {
        let configs = vec![
            bare_config("http_ingestion", "http"),
            bare_config("vector_ingestion", "vector"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        let routes: Vec<&String> = inputs.iter().filter(|s| s.ends_with("_route")).collect();
        assert_eq!(
            routes.len(),
            1,
            "exactly one source_type_extract route must feed source_router, got {inputs:?}"
        );
        // Channel covered → direct source_type_extract dropped; vector_merge stays.
        assert!(!inputs.iter().any(|s| s == "source_type_extract"), "{inputs:?}");
        assert!(inputs.iter().any(|s| s == "vector_merge"), "{inputs:?}");
    }

    /// NAN-1442 guard: distinct channels must NOT be collapsed. `http`
    /// (source_type_extract) + `splunk_hec` (hec_normalize) read different
    /// always-on channels, so both routes stay and neither method is dropped.
    #[test]
    fn compute_router_inputs_keeps_routes_for_distinct_channels() {
        let configs = vec![
            bare_config("http_ingestion", "http"),
            bare_config("splunk_main", "splunk_hec"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        let routes: Vec<&String> = inputs.iter().filter(|s| s.ends_with("_route")).collect();
        assert_eq!(routes.len(), 2, "both distinct-channel routes must stay, got {inputs:?}");
        assert!(!inputs.iter().any(|s| s == "source_type_extract"), "{inputs:?}");
        assert!(!inputs.iter().any(|s| s == "hec_normalize"), "{inputs:?}");
    }

    /// NAN-1442 guard: non-system fetch sources (kafka/s3/...) own distinct
    /// upstreams and must never be deduped against each other.
    #[test]
    fn compute_router_inputs_keeps_all_non_system_routes() {
        let configs = vec![
            bare_config("kafka_a", "kafka"),
            bare_config("kafka_b", "kafka"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        let routes: Vec<&String> = inputs.iter().filter(|s| s.ends_with("_route")).collect();
        assert_eq!(routes.len(), 2, "non-system routes must not be deduped, got {inputs:?}");
    }

    #[test]
    fn system_intermediary_source_maps_http_and_vector_to_source_type_extract() {
        assert_eq!(
            SourceConfigService::system_intermediary_source("http"),
            Some("source_type_extract")
        );
        assert_eq!(
            SourceConfigService::system_intermediary_source("vector"),
            Some("source_type_extract")
        );
    }

    /// Guards NAN-853: splunk_hec deploys must route via `hec_normalize`,
    /// not declare a new `[sources.*]` on :8088 that collides with the OOTB
    /// splunk_hec_ingest source.
    #[test]
    fn system_intermediary_source_maps_splunk_hec_to_hec_normalize() {
        assert_eq!(
            SourceConfigService::system_intermediary_source("splunk_hec"),
            Some("hec_normalize")
        );
    }

    #[test]
    fn system_intermediary_source_is_none_for_owned_source_types() {
        for ty in ["kafka", "aws_s3", "gcp_pubsub", "unknown"] {
            assert_eq!(
                SourceConfigService::system_intermediary_source(ty),
                None,
                "{ty} owns its source and must not be treated as system-level"
            );
        }
    }

    #[test]
    fn system_source_renderer_emits_only_meaningful_routes() {
        let routed = make_config(
            "http",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("windows"),
                "windows_event",
            )],
        );
        let rendered = SourceConfigService::render_system_source_config(
            &routed,
            "source_type_extract",
        )
        .expect("non-default system rule should render");
        assert!(rendered.contains("[transforms.test_source_route]"));
        assert!(rendered.contains("inputs = [\"source_type_extract\"]"));

        let passthrough = make_config(
            "http",
            vec![make_rule(1000, "source_type", "default", None, "unknown")],
        );
        assert!(
            SourceConfigService::render_system_source_config(
                &passthrough,
                "source_type_extract",
            )
            .is_none(),
            "a passthrough-only system source must not create a duplicate route"
        );
    }

    /// End-to-end shape of the generated routing TOML for a splunk_hec deploy:
    /// transform-only, consumes from `hec_normalize`, no `[sources.*]` block.
    #[test]
    fn splunk_hec_routing_transform_consumes_hec_normalize_with_no_source_block() {
        let intermediary = SourceConfigService::system_intermediary_source("splunk_hec")
            .expect("splunk_hec must be system-level");
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(
                10,
                "sourcetype",
                "exact",
                Some("access_combined"),
                "apache_access",
            )],
        );

        let routing = SourceConfigService::generate_routing_transform(
            &cfg,
            intermediary,
            "splunk_hec_test_route",
            true,
        );

        assert!(
            !routing.contains("[sources."),
            "routing transform must not declare a Vector source — would collide with OOTB \
             splunk_hec_ingest on :8088. got:\n{routing}"
        );
        assert!(
            routing.contains("inputs = [\"hec_normalize\"]"),
            "routing transform must consume from hec_normalize, got:\n{routing}"
        );
        assert!(
            routing.contains("[transforms.splunk_hec_test_route]"),
            "routing transform name must be present, got:\n{routing}"
        );
    }

    /// NAN-918: HEC now uses HTTP-parity passthrough-default semantics.
    /// A default rule on a HEC config preserves `.source_type` (set by
    /// hec_normalize from the envelope's sourcetype), so imported parsers
    /// with various sourcetypes route correctly without per-parser rules.
    /// Users who need "force all events to <X>" can express that with a
    /// non-default rule (e.g. regex `.*`).
    ///
    /// Supersedes the pre-NAN-918 NAN-856 "default target is authoritative"
    /// semantic — HEC was reclassified as push in NAN-883, matching HTTP/Vector.
    #[test]
    fn splunk_hec_default_only_rule_emits_passthrough() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "unknown")],
        );

        // Mirrors what deploy() passes for splunk_hec post-NAN-918:
        // intermediary=hec_normalize, system_level=true (passthrough default).
        let routing = SourceConfigService::generate_routing_transform(
            &cfg,
            "hec_normalize",
            "splunk_hec_test_route",
            true,
        );

        assert!(
            routing.contains("passthrough"),
            "default rule must coalesce to passthrough for HEC post-NAN-918, got:\n{routing}"
        );
        assert!(
            !routing.contains(".source_type = \"unknown\""),
            "stored default target must NOT be emitted as unconditional assignment, got:\n{routing}"
        );
    }

    /// Guards NAN-856 defense-in-depth: compute_router_inputs must skip
    /// system-level configs (http/vector/splunk_hec) whose routing TOML is
    /// not on disk, even if marked deployed in DB. Otherwise source_router
    /// gets an input pointing at a non-existent transform and Vector aborts.
    #[test]
    fn compute_router_inputs_skips_splunk_hec_when_no_file_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert!(
            !inputs.iter().any(|s| s == "hec_main_route"),
            "splunk_hec route must not be in inputs when no file on disk, got: {inputs:?}"
        );
        // hec_normalize must still be present unconditionally.
        assert!(inputs.iter().any(|s| s == "hec_normalize"));
    }

    /// HEC with no rules at all: nothing to deploy. has_meaningful_rules
    /// must return false so deploy() skips the file write — hec_normalize's
    /// envelope-derived `.source_type` flows directly to parser matching.
    #[test]
    fn has_meaningful_routing_rules_false_for_splunk_hec_with_empty_rules() {
        let cfg = make_config("splunk_hec", vec![]);
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// NAN-918: HEC default-only rules are now passthrough (HTTP-parity),
    /// so they're no-ops just like HTTP's. has_meaningful_routing_rules
    /// returns false — same as HTTP — so deploy() skips the file write.
    /// Previously (NAN-856) HEC defaults were authoritative and a
    /// default-only config DID require the file; that semantic was reverted
    /// once HEC was reclassified as push.
    #[test]
    fn has_meaningful_routing_rules_false_for_splunk_hec_with_default_only() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "unknown")],
        );
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// HTTP/Vector with a default-only rule: existing behavior must be
    /// preserved — default rules are passthrough no-ops, so the file is
    /// skipped. Guards against accidental regression of the
    /// http/vector deploy semantics during NAN-856.
    #[test]
    fn has_meaningful_routing_rules_false_for_http_with_default_only() {
        let cfg = make_config(
            "http",
            vec![make_rule(1000, "source_type", "default", None, "something")],
        );
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    #[test]
    fn has_meaningful_routing_rules_true_for_http_with_non_default_rule() {
        let cfg = make_config(
            "http",
            vec![make_rule(10, "host", "exact", Some("web1"), "apache_access")],
        );
        assert!(SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// NAN-1572: OTLP is always default-passthrough — even a non-default rule
    /// must NOT make it write an `otlp_route` (which would double-write
    /// parser-claimed events off `otlp_logs_prep`). OTLP logs route via parser
    /// match_values until the envelope mapping (NAN-1556).
    #[test]
    fn has_meaningful_routing_rules_false_for_otlp_even_with_non_default_rule() {
        let cfg = make_config(
            "otlp",
            vec![make_rule(10, "source_type", "exact", Some("otlp_log"), "json_generic")],
        );
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// NAN-857: when a splunk_hec route IS on disk, `hec_normalize` must be
    /// suppressed from base inputs — the route consumes hec_normalize and
    /// feeds source_router, so keeping hec_normalize as a direct base input
    /// would double-ingest every HEC event (once direct → source_type=unknown,
    /// once via the route → user-configured source_type). And — separately —
    /// splunk_hec must NOT suppress source_type_extract; HEC and HTTP are
    /// independent channels.
    ///
    /// NAN-940: the splunk_hec route is pinned to `splunk_hec_route`
    /// regardless of the user-facing config name — `bare_config("hec_main",
    /// "splunk_hec")` resolves to the pinned route, not `hec_main_route`.
    #[test]
    fn compute_router_inputs_suppresses_hec_normalize_when_splunk_hec_route_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "otlp_logs_prep", "splunk_hec_route"],
            "hec_normalize must be intermediated by the splunk_hec route, not also direct"
        );
    }

    /// Both intermediaries covered: only vector_merge + the two routes.
    /// NAN-940: the splunk_hec route stays pinned even when paired with a
    /// renamed http config (which is NOT pinned — http_main → http_main_route).
    #[test]
    fn compute_router_inputs_suppresses_both_intermediaries_when_both_routes_on_disk() {
        let configs = vec![
            bare_config("http_main", "http"),
            bare_config("hec_main", "splunk_hec"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["vector_merge", "otlp_logs_prep", "http_main_route", "splunk_hec_route"]
        );
    }

    /// NAN-1572: defensive coverage of the `otlp_logs_prep_covered` flag in
    /// `compute_router_inputs` — IF an otlp route were on disk, `otlp_logs_prep`
    /// must be suppressed from base inputs so the channel doesn't reach
    /// `source_router` twice (NAN-1442 Saturn 2× class). In practice
    /// `has_meaningful_routing_rules` keeps OTLP default-passthrough so no otlp
    /// route file is written (see that test); this exercises the pure suppression
    /// path directly. The otlp route name is rename-derived (not pinned).
    #[test]
    fn compute_router_inputs_suppresses_otlp_logs_prep_when_otlp_route_on_disk() {
        let configs = vec![bare_config("otlp_main", "otlp")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "hec_normalize", "otlp_main_route"],
            "otlp_logs_prep must be intermediated by the otlp route, not also direct"
        );
    }

    /// NAN-1572: an otlp config with NO route file on disk (default-only rules)
    /// must NOT suppress `otlp_logs_prep` — the direct base input is the only
    /// path OTLP logs reach source_router, mirroring the splunk_hec skip case.
    #[test]
    fn compute_router_inputs_keeps_otlp_logs_prep_when_no_otlp_file_on_disk() {
        let configs = vec![bare_config("otlp_main", "otlp")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert!(
            inputs.iter().any(|s| s == "otlp_logs_prep"),
            "otlp_logs_prep must stay a direct base input when no otlp route is on disk: {inputs:?}"
        );
        assert!(
            !inputs.iter().any(|s| s == "otlp_route"),
            "no otlp route should be wired when its file isn't on disk: {inputs:?}"
        );
    }

    /// NAN-940 regression: a user renaming the OOTB splunk_hec config to an
    /// arbitrary string must NOT change the route-transform name. HEC
    /// parsers hardcode `splunk_hec_route` via `parser_claimed_route` —
    /// a rename-derived `<safe_name>_route` would orphan every HEC parser.
    #[test]
    fn config_route_name_pinned_for_splunk_hec_across_rename() {
        for renamed in [
            "Splunk HEC",
            "Foo",
            "My HEC",
            "internal-audit",
            "  weird   spaces  ",
        ] {
            assert_eq!(
                SourceConfigService::config_route_name("splunk_hec", renamed),
                "splunk_hec_route",
                "splunk_hec route name must be pinned regardless of user-facing name (was: {renamed})",
            );
        }

        // Non-singleton drivers still derive from the user-facing name.
        assert_eq!(
            SourceConfigService::config_route_name("kafka", "Prod-Kafka"),
            "prod_kafka_route",
        );
        assert_eq!(
            SourceConfigService::config_route_name("http", "Main"),
            "main_route",
        );
    }

    /// NAN-940: the on-disk file stem is also pinned for splunk_hec so a
    /// rename can't strand the old file on disk AND collide on the pinned
    /// transform name when the new file is written.
    #[test]
    fn config_safe_stem_pinned_for_splunk_hec_across_rename() {
        for renamed in ["Splunk HEC", "Foo", "Renamed HEC"] {
            assert_eq!(
                SourceConfigService::config_safe_stem("splunk_hec", renamed),
                "splunk_hec",
            );
        }
        // Non-singleton drivers still vary by name.
        assert_eq!(
            SourceConfigService::config_safe_stem("kafka", "Prod-Kafka"),
            "prod_kafka",
        );
    }

    // ------------------------------------------------------------------
    // NAN-930: claim-based substitution for the surgical inputs rewrite.
    // ------------------------------------------------------------------

    fn claim(route: &str, parser: &str, match_values: &[&str]) -> RouteClaim {
        RouteClaim {
            route: route.to_string(),
            parser_name: parser.to_string(),
            match_values: match_values.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Sanity: no claims → identity mapping (no substitution).
    #[test]
    fn build_claim_substitutions_is_empty_when_no_claims() {
        let subs = SourceConfigService::build_claim_substitutions(&[]);
        assert!(subs.is_empty());
    }

    /// Single claimant produces a `<route>_unclaimed` substitution.
    #[test]
    fn build_claim_substitutions_maps_route_to_unclaimed_name() {
        let claims = vec![claim("kafka_x_route", "Apache HTTP Server", &["apache_access"])];
        let subs = SourceConfigService::build_claim_substitutions(&claims);
        assert_eq!(subs.get("kafka_x_route").map(String::as_str), Some("kafka_x_route_unclaimed"));
        // Routes not in the claim list aren't substituted.
        assert!(subs.get("vector_merge").is_none());
    }

    /// Two claimants of the same route collapse to one substitution.
    #[test]
    fn build_claim_substitutions_dedupes_multiple_claimants() {
        let claims = vec![
            claim("splunk_hec_route", "apache", &["apache_access"]),
            claim("splunk_hec_route", "nginx", &["nginx"]),
        ];
        let subs = SourceConfigService::build_claim_substitutions(&claims);
        assert_eq!(subs.len(), 1);
        assert_eq!(
            subs.get("splunk_hec_route").map(String::as_str),
            Some("splunk_hec_route_unclaimed"),
        );
    }

    /// Emit a filter block with the union of match_values, negated so
    /// source_router only gets the leftover stream. Post-NAN-930 this is
    /// a clean rewrite — there is no "skip when present" branch; the
    /// strip step handles dedup at the file level.
    #[test]
    fn build_unclaimed_blocks_emits_block_with_sorted_dedup_values() {
        let claims = vec![claim("kafka_x_route", "Apache HTTP Server", &["apache_access", "apache"])];
        let blocks = SourceConfigService::build_unclaimed_blocks(&claims);
        assert!(blocks.contains("[transforms.kafka_x_route_unclaimed]"), "blocks=\n{blocks}");
        assert!(blocks.contains("type = \"filter\""));
        assert!(blocks.contains("inputs = [\"kafka_x_route\"]"));
        // Match values are sorted+deduped before negation.
        assert!(blocks.contains(r#"'!includes(["apache", "apache_access"], to_string(.source_type) ?? "")'"#),
            "blocks=\n{blocks}");
    }

    /// Empty match_values falls back to the parser name (matches what
    /// `build_hec_filter_condition` in parsers/vector_config/sources.rs does).
    #[test]
    fn build_unclaimed_blocks_falls_back_to_parser_name_when_match_values_empty() {
        let claims = vec![claim("kafka_x_route", "lone_parser", &[])];
        let blocks = SourceConfigService::build_unclaimed_blocks(&claims);
        assert!(blocks.contains(r#"["lone_parser"]"#), "blocks=\n{blocks}");
    }

    /// Strip removes a `[transforms.X_unclaimed]` block while preserving
    /// surrounding sections — handles the NAN-930 #2 case (changed
    /// match_values must regenerate the condition).
    #[test]
    fn strip_existing_unclaimed_blocks_removes_unclaimed_section() {
        let content = "[transforms.foo]\ntype = \"remap\"\n\
                       [transforms.kafka_x_route_unclaimed]\ntype = \"filter\"\ncondition = 'stale'\n\
                       [transforms.source_router]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(!stripped.contains("[transforms.kafka_x_route_unclaimed]"),
            "expected unclaimed section removed, got:\n{stripped}");
        assert!(!stripped.contains("'stale'"), "expected stale condition removed");
        // Other sections survive.
        assert!(stripped.contains("[transforms.foo]"));
        assert!(stripped.contains("[transforms.source_router]"));
    }

    /// Strip removes multiple unclaimed blocks — handles a deploy where
    /// several source-configs were renamed/deleted simultaneously.
    #[test]
    fn strip_existing_unclaimed_blocks_removes_multiple_blocks() {
        let content = "[transforms.a_unclaimed]\ntype = \"filter\"\n\
                       [transforms.keep_me]\ntype = \"remap\"\n\
                       [transforms.b_unclaimed]\ntype = \"filter\"\n\
                       [transforms.also_keep]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(!stripped.contains("a_unclaimed"));
        assert!(!stripped.contains("b_unclaimed"));
        assert!(stripped.contains("[transforms.keep_me]"));
        assert!(stripped.contains("[transforms.also_keep]"));
    }

    /// Strip with no unclaimed blocks returns the content unchanged
    /// (modulo trailing newline normalization).
    #[test]
    fn strip_existing_unclaimed_blocks_is_noop_when_no_blocks() {
        let content = "[transforms.foo]\ntype = \"remap\"\n[transforms.source_router]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(stripped.contains("[transforms.foo]"));
        assert!(stripped.contains("[transforms.source_router]"));
        // No unclaimed mentions
        assert!(!stripped.contains("_unclaimed"));
    }

    /// Strip does NOT match comment lines that happen to mention
    /// `_unclaimed`. Only `[transforms.X_unclaimed]` headers count.
    #[test]
    fn strip_existing_unclaimed_blocks_ignores_comment_mentions() {
        let content = "# NAN-930: _unclaimed comment\n\
                       [transforms.foo]\ntype = \"remap\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        // Comment line survives (we only strip section bodies, not comments).
        assert!(stripped.contains("# NAN-930: _unclaimed comment"));
        assert!(stripped.contains("[transforms.foo]"));
    }

    // ----------------------------------------------------------------------
    // NAN-946: validate_safe_strings depth cap. Admin-controlled JSON
    // payloads on connection_config must not be able to overflow the
    // runtime stack via deeply-nested objects/arrays.
    // ----------------------------------------------------------------------

    /// Build a JSON object nested `depth` levels deep:
    /// `{"k": {"k": {"k": ... "leaf"}}}`
    fn nested_object(depth: usize) -> serde_json::Value {
        let mut v = serde_json::Value::String("leaf".to_string());
        for _ in 0..depth {
            let mut obj = serde_json::Map::new();
            obj.insert("k".to_string(), v);
            v = serde_json::Value::Object(obj);
        }
        v
    }

    /// Build a JSON array nested `depth` levels deep: `[[[..."leaf"...]]]`.
    fn nested_array(depth: usize) -> serde_json::Value {
        let mut v = serde_json::Value::String("leaf".to_string());
        for _ in 0..depth {
            v = serde_json::Value::Array(vec![v]);
        }
        v
    }

    #[test]
    fn validate_safe_strings_accepts_realistic_connection_configs() {
        // Real Kafka shape: one-level object with arrays of strings.
        let kafka = serde_json::json!({
            "bootstrap_servers": "broker1:9092,broker2:9092",
            "topics": ["audit", "app", "infra"],
            "group_id": "nanosiem-prod",
            "sasl": {
                "mechanism": "SCRAM-SHA-512",
                "username": "nano",
            }
        });
        assert!(SourceConfigService::validate_safe_strings(&kafka, "connection_config").is_ok());

        // HEC: typically empty.
        assert!(
            SourceConfigService::validate_safe_strings(
                &serde_json::json!({}),
                "connection_config"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_safe_strings_accepts_depth_at_the_cap() {
        // Depth == cap is fine; depth > cap is the rejection.
        let v = nested_object(crate::config_safety::MAX_CONFIG_DEPTH);
        assert!(
            SourceConfigService::validate_safe_strings(&v, "connection_config").is_ok(),
            "object at the exact cap must still validate"
        );
    }

    #[test]
    fn validate_safe_strings_rejects_object_past_depth_cap() {
        let v = nested_object(crate::config_safety::MAX_CONFIG_DEPTH + 5);
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected depth-cap rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("nesting depth"),
            "error must mention nesting depth: {msg}"
        );
    }

    #[test]
    fn validate_safe_strings_rejects_array_past_depth_cap() {
        let v = nested_array(crate::config_safety::MAX_CONFIG_DEPTH + 5);
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected depth-cap rejection");
        let msg = err.to_string();
        assert!(msg.contains("nesting depth"), "error must mention nesting depth: {msg}");
    }

    // ----------------------------------------------------------------------
    // NAN-947: rename cleanup — when a non-singleton source-config is
    // renamed, the old .toml file on disk would otherwise linger as an
    // orphan. `update()` snapshots the pre-rename path, compares against
    // the post-rename path, and removes the old file if they differ.
    // ----------------------------------------------------------------------

    #[test]
    fn rename_changes_on_disk_stem_true_for_kafka_rename() {
        assert!(
            SourceConfigService::rename_changes_on_disk_stem(
                "kafka", "Prod-Kafka", "kafka", "Renamed-Kafka",
            ),
            "kafka rename must change the on-disk stem so the orphan can be cleaned up",
        );
    }

    #[test]
    fn rename_changes_on_disk_stem_false_for_splunk_hec_rename() {
        // NAN-940 pins splunk_hec's file stem regardless of name; a rename
        // does NOT change the stem, so the cleanup branch must be a no-op.
        assert!(
            !SourceConfigService::rename_changes_on_disk_stem(
                "splunk_hec", "Splunk HEC", "splunk_hec", "Renamed HEC",
            ),
            "splunk_hec rename must NOT change the on-disk stem (pinned by NAN-940)",
        );
    }

    #[test]
    fn rename_changes_on_disk_stem_false_when_name_identical() {
        assert!(!SourceConfigService::rename_changes_on_disk_stem(
            "kafka", "Audit-Kafka", "kafka", "Audit-Kafka",
        ));
    }

    #[test]
    fn rename_changes_on_disk_stem_false_when_safe_name_collides() {
        // safe_name() lowercases + replaces non-alphanumerics → both
        // "Prod-Kafka" and "prod kafka" resolve to "prod_kafka". A
        // user-visible rename between two such names is a no-op on disk,
        // so we should NOT try to delete the file that's still active.
        // (Distinct configs colliding is the M9 / NAN-952 concern, not
        // ours — but this test pins the cleanup-is-stem-based invariant.)
        assert!(!SourceConfigService::rename_changes_on_disk_stem(
            "kafka", "Prod-Kafka", "kafka", "prod kafka",
        ));
    }

    #[test]
    fn validate_safe_strings_still_rejects_control_chars_inside_nested() {
        // Depth check must not short-circuit before the control-char check
        // on the way down.
        let v = serde_json::json!({
            "outer": {
                "inner": {
                    "bad": "line\nbreak",
                }
            }
        });
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected control-char rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("control character"),
            "error must mention control character: {msg}"
        );
    }

    // ----------------------------------------------------------------------
    // NAN-948: deploy_lock sharing. The `with_deploy_lock` builder accepts
    // an `Arc<Mutex<()>>` shared with VectorConfigManager so that
    // `update_dynamic_router`'s read-mutate-write of `_router.toml` is
    // serialized against parser deploys. The wire-up at API startup
    // (state/constructors.rs) is integration-tested via cargo build; here
    // we cover the core invariant: `VectorConfigManager::deploy_lock()`
    // hands out the same Arc on every call (clone, not new), so a downstream
    // service receives a lock that actually blocks the manager's own writes.
    // ----------------------------------------------------------------------

    #[tokio::test]
    async fn vector_config_manager_deploy_lock_is_shared_not_cloned_anew() {
        use crate::parsers::VectorConfigManager;
        let vcm = VectorConfigManager::new(std::path::PathBuf::from("/tmp/nanosiem-test"));
        let lock_a = vcm.deploy_lock();
        let lock_b = vcm.deploy_lock();
        assert!(
            std::sync::Arc::ptr_eq(&lock_a, &lock_b),
            "deploy_lock() must hand out clones of the SAME Arc, not new Arcs — otherwise the lock would not serialize across services"
        );

        // Acquiring lock_a blocks lock_b — same mutex, mutually exclusive.
        let _outer = lock_a.lock().await;
        assert!(
            lock_b.try_lock().is_err(),
            "lock acquired via one handle must block subsequent try_lock on a clone of the same Arc",
        );
    }

    #[test]
    fn canonical_source_render_requires_parser_router_first() {
        let root = tempfile::tempdir().unwrap();
        let error = SourceConfigService::require_canonical_router(root.path())
            .expect_err("a source render without the parser router must fail closed");
        let is_precondition_error = matches!(
            &error,
            SourceConfigServiceError::InvalidConfig(message)
                if message.contains("parser router")
        );
        assert!(
            is_precondition_error,
            "unexpected error: {error}"
        );

        let router = root.path().join("sources/parsers/_router.toml");
        std::fs::create_dir_all(router.parent().unwrap()).unwrap();
        std::fs::write(&router, "[transforms.source_router]\n").unwrap();
        SourceConfigService::require_canonical_router(root.path())
            .expect("an existing canonical router should satisfy the render precondition");
    }

    #[test]
    fn publication_renderer_forces_credentials_into_snapshot_directory() {
        let root = tempfile::tempdir().unwrap();
        let runtime_path = "/etc/vector/runtime/current".to_string();
        let backend = SourceConfigService::publication_creds_backend(
            root.path().to_path_buf(),
            runtime_path.clone(),
        );

        assert!(matches!(
            backend,
            CredsBackend::Disk { config_dir, runtime_path: actual }
                if config_dir == root.path() && actual == runtime_path
        ));
    }

    // ----------------------------------------------------------------------
    // NAN-952: creds_filename_stem must be unique-per-config_id and not
    // derived from the user-facing name (where safe_name() collisions
    // would let one config's deploy overwrite another's CA / GCP JSON).
    // ----------------------------------------------------------------------

    #[test]
    fn creds_filename_stem_returns_uuid_string() {
        let id = Uuid::parse_str("30000000-0000-0000-0000-000000000003").unwrap();
        assert_eq!(
            SourceConfigService::creds_filename_stem(&id),
            "30000000-0000-0000-0000-000000000003",
        );
    }

    #[test]
    fn creds_filename_stem_differs_for_distinct_configs_even_with_same_safe_name() {
        // Two configs that would have collided under the old safe_name(name)
        // approach. Their stem must differ — that's the whole point of
        // NAN-952.
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        assert_ne!(
            SourceConfigService::creds_filename_stem(&id_a),
            SourceConfigService::creds_filename_stem(&id_b),
            "distinct UUIDs must produce distinct filename stems",
        );
    }

    #[test]
    fn creds_filename_stem_is_filesystem_safe() {
        // Hyphenated UUID is [0-9a-f-]+ — no spaces, slashes, dots, or
        // shell metachars. ConfigMap-mount-safe (K8s flattens dirs but
        // keys can't contain `/`).
        let id = Uuid::new_v4();
        let stem = SourceConfigService::creds_filename_stem(&id);
        for c in stem.chars() {
            assert!(
                c.is_ascii_hexdigit() || c == '-',
                "stem must contain only [0-9a-f-]: got '{c}' in {stem}",
            );
        }
        // 36-char canonical UUID form. Allows our `kafka_{stem}.ca.pem`
        // filename to stay under typical filesystem name limits (255).
        assert_eq!(stem.len(), 36);
    }
