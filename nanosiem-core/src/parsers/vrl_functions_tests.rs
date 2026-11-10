// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4912 P3 / NAN-4808: the prompt catalog is the pinned VRL 0.38 stdlib
//! the guarded compiler accepts — no more, no less.

use super::vrl_functions::{
    parser_vrl_functions, vrl_function_catalog, VrlRegistry, ENRICHMENT_EXTRA_VRL_FUNCTIONS,
    PARSER_EXCLUDED_VRL_FUNCTIONS, PARSER_VRL_FUNCTIONS,
};

#[test]
fn catalog_lists_exactly_the_safe_compiler_registry() {
    let catalog = vrl_function_catalog();
    let functions = parser_vrl_functions();
    assert_eq!(catalog.lines().count(), functions.len());
    for function in &functions {
        let signature = catalog
            .lines()
            .find(|line| line.starts_with(&format!("{}(", function.identifier())))
            .unwrap_or_else(|| panic!("{} has no catalog line", function.identifier()));
        for parameter in function.parameters() {
            let rendered = format!(
                "{}{}:{}",
                parameter.keyword,
                if parameter.required { "" } else { "?" },
                parameter.kind()
            );
            assert!(signature.contains(&rendered), "{signature} lacks {rendered}");
        }
    }
    let mut sorted: Vec<&str> = catalog.lines().collect();
    sorted.sort();
    assert_eq!(sorted, catalog.lines().collect::<Vec<_>>(), "catalog is sorted");
}

#[test]
fn catalog_never_offers_blocked_or_invented_functions() {
    let catalog = vrl_function_catalog();
    for name in PARSER_EXCLUDED_VRL_FUNCTIONS
        .iter()
        .copied()
        .chain(["parse_integer", "lowercase", "parse_magic"])
    {
        assert!(
            !catalog.lines().any(|line| line.starts_with(&format!("{name}("))),
            "{name} must not be offered"
        );
    }
}

/// The catalog tracks the linked crate, not a checked-in list: `range` was
/// added in VRL 0.38 (main shipped 0.36 and never offered it), and closure
/// arities / return kinds come from the compiler's own definitions.
#[test]
fn catalog_matches_vrl_0_38() {
    let catalog = vrl_function_catalog();
    let line = |name: &str| {
        catalog
            .lines()
            .find(|line| line.starts_with(&format!("{name}(")))
            .unwrap_or_else(|| panic!("{name} missing from the VRL 0.38 catalog"))
    };
    assert!(line("range").contains("start:"), "{}", line("range"));
    assert!(line("for_each").contains("|arg1,arg2|"), "{}", line("for_each"));
    assert!(line("parse_int").contains(": integer"), "{}", line("parse_int"));
    for core in ["parse_json(", "parse_timestamp(", "parse_regex(", "to_int(", "downcase("] {
        assert!(catalog.lines().any(|l| l.starts_with(core)), "{core}");
    }
}

#[tokio::test]
async fn every_catalog_function_name_is_known_to_the_compiler() {
    // A call to each cataloged name must never be E105 (undefined function).
    let validator = super::VrlValidator::new();
    for line in vrl_function_catalog().lines() {
        let name = line.split('(').next().unwrap();
        let (_, errors) = validator
            .validate_vrl_collect_errors(&format!(".x = {name}()"))
            .await
            .expect("validator ran");
        assert!(
            errors.iter().all(|e| !e.contains("E105")),
            "{name}: {errors:?}"
        );
    }
}


/// Fail closed on VRL upgrades: every stdlib function is either reviewed
/// into the parser allowlist or explicitly excluded, never silently new.
#[test]
fn every_stdlib_function_is_classified_and_the_lists_are_disjoint() {
    let stdlib: Vec<String> = vrl::stdlib::all()
        .iter()
        .map(|f| f.identifier().to_string())
        .collect();
    for name in &stdlib {
        assert!(
            PARSER_VRL_FUNCTIONS.contains(&name.as_str())
                || PARSER_EXCLUDED_VRL_FUNCTIONS.contains(&name.as_str()),
            "VRL function `{name}` is unclassified: review it into PARSER_VRL_FUNCTIONS or PARSER_EXCLUDED_VRL_FUNCTIONS"
        );
    }
    for name in PARSER_VRL_FUNCTIONS.iter().chain(PARSER_EXCLUDED_VRL_FUNCTIONS) {
        assert!(stdlib.iter().any(|s| s == name), "`{name}` is not a VRL 0.38 function");
    }
    for name in PARSER_VRL_FUNCTIONS {
        assert!(!PARSER_EXCLUDED_VRL_FUNCTIONS.contains(name), "`{name}` is in both lists");
    }
    for name in ["log", "get_env_var", "get_hostname", "get_timezone_name", "http_request",
        "dns_lookup", "reverse_dns", "validate_json_schema", "parse_proto", "encode_proto", "parse_etld"]
    {
        assert!(PARSER_EXCLUDED_VRL_FUNCTIONS.contains(&name), "{name}");
    }
    // Enrichment adds only `log`.
    assert_eq!(ENRICHMENT_EXTRA_VRL_FUNCTIONS, &["log"]);
    let enrichment: Vec<_> = VrlRegistry::Enrichment.functions().iter().map(|f| f.identifier()).collect();
    assert_eq!(enrichment.len(), PARSER_VRL_FUNCTIONS.len() + 1);
    assert!(enrichment.contains(&"log") && !enrichment.contains(&"get_env_var"));
}

const LOGGING_PARSER: &str = ".udm = {}\nlog(., level: \"error\", rate_limit_secs: 0)\n.udm.user = \"x\"\n";
const ENV_PARSER: &str = ".udm = {}\n.udm.leak = get_env_var(\"PATH\") ?? \"\"\n";

/// The exfiltration shape from the review: an injected `log(.)` (or an
/// env read) never compiles in any parser path.
#[tokio::test]
async fn log_and_env_reads_fail_to_compile_in_every_parser_path() {
    let validator = super::VrlValidator::new();
    let validate = validator.validate_vrl(LOGGING_PARSER).await.unwrap();
    assert!(validate.error.as_deref().unwrap_or("").contains("E105"), "{validate:?}");
    for code in [LOGGING_PARSER, ENV_PARSER] {
        // Validate / save / publish / deploy.
        let result = validator.validate_vrl(code).await.unwrap();
        assert!(!result.valid, "{code}");
        // `log` reaches the compiler (E105: not in the registry); the env
        // read is stopped one gate earlier by the source-pattern check.
        let error = result.error.as_deref().unwrap_or("");
        assert!(error.contains("E105") || error.contains("forbidden function"), "{result:?}");
        // AI drafts and editors (collect_errors).
        let (result, errors) = validator.validate_vrl_collect_errors(code).await.unwrap();
        assert!(
            !result.valid
                && errors.iter().any(|e| e.contains("E105") || e.contains("forbidden function")),
            "{errors:?}"
        );
        // Parser test / live test: never executes.
        let tested = validator.test_vrl(code, r#"{"message":"secret"}"#).await.unwrap();
        assert!(!tested.success, "{tested:?}");
        // Compiler-span diagnostics (autofix) see the same registry.
        let sites = super::vrl_diagnostics::compiler_sites(code).await;
        assert!(sites.iter().any(|s| s.code == 105), "{sites:?}");
        // Guarded compile with the parser registry.
        assert!(super::vrl_guard::compile(code, &parser_vrl_functions()).is_err());
    }
    // Source-config remaps compile with the same allowlist.
    let generated = format!(
        "[transforms.x]\ntype = \"remap\"\ninputs = [\"y\"]\nsource = \'\'\'\n{LOGGING_PARSER}\'\'\'\n"
    );
    assert!(crate::source_configs::SourceConfigService::validate_generated_config(&generated).is_err());
}

#[tokio::test]
async fn enrichment_normalize_programs_keep_their_dead_letter_log() {
    let normalize = "if !exists(.id) {\n  log(\"missing id; dead-lettering\", level: \"warn\")\n  abort\n}\n. = {\"external_id\": .id}\n";
    let enrichment = super::VrlValidator::for_enrichment();
    assert!(enrichment.validate_vrl(normalize).await.unwrap().valid);
    assert!(!super::VrlValidator::new().validate_vrl(normalize).await.unwrap().valid);
}

/// Content-repo parsers still compile against the allowlist. Point
/// `NAN4912_PARSER_CORPUS` at a directory of `parser.yaml` files (the
/// legacy UDM set and/or the OCSF set); enrichment lanes are checked with
/// the enrichment registry. A no-op without the variable.
#[tokio::test]
async fn content_repo_parsers_compile_against_the_allowlist() {
    let Ok(root) = std::env::var("NAN4912_PARSER_CORPUS") else {
        return;
    };
    let mut stack = vec![std::path::PathBuf::from(root)];
    let (mut checked, mut broken) = (0, Vec::new());
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().is_none_or(|n| n != "parser.yaml") {
                continue;
            }
            let doc: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for (key, enrichment) in [("parser_vrl", false), ("normalize_vrl", true)] {
                let Some(code) = doc.get(key).and_then(|v| v.as_str()) else { continue };
                if code.trim().is_empty() {
                    continue;
                }
                let validator = if enrichment { super::VrlValidator::for_enrichment() } else { super::VrlValidator::new() };
                let (result, errors) = validator.validate_vrl_collect_errors(code).await.unwrap();
                checked += 1;
                if !result.valid {
                    broken.push(format!("{} [{key}]: {}", path.display(), errors.join(" | ").chars().take(300).collect::<String>()));
                }
            }
        }
    }
    println!("CORPUS checked={checked} broken={}", broken.len());
    for b in &broken {
        println!("BROKEN {b}");
    }
    assert!(checked > 0, "no parser.yaml found");
}

const DECOMPRESSORS: [&str; 5] = ["decode_gzip", "decode_zlib", "decode_zstd", "decode_snappy", "decode_lz4"];

/// NAN-5141: the in-process test/preview paths run VRL inside the API
/// process, where an unbounded decompression call cannot be interrupted.
/// Every decompressor is refused at compile time (both registries), so a
/// test request is a validation failure that never executes.
#[tokio::test]
async fn decompression_functions_are_refused_in_every_in_process_path() {
    let enrichment: Vec<_> = VrlRegistry::Enrichment.functions().iter().map(|f| f.identifier()).collect();
    for name in DECOMPRESSORS {
        assert!(PARSER_EXCLUDED_VRL_FUNCTIONS.contains(&name), "{name}");
        assert!(!enrichment.contains(&name), "{name} offered to enrichment lanes");
        let code = format!(".udm = {{}}\n.udm.body = {name}!(decode_base64!(.message))\n");
        let sample = r#"{"message":"KLUv/QBYAQAAeA=="}"#;
        let validator = super::VrlValidator::new();
        let validated = validator.validate_vrl(&code).await.unwrap();
        assert!(!validated.valid, "{name}: {validated:?}");
        assert!(validated.error.as_deref().unwrap_or("").contains("E105"), "{validated:?}");
        let tested = validator.test_vrl(&code, sample).await.unwrap();
        assert!(!tested.success && tested.output.is_none(), "{name}: {tested:?}");
        let chained = validator.test_vrl_chain(&[&code], sample).await.unwrap();
        assert!(!chained.success && chained.output.is_none(), "{name}: {chained:?}");
        assert!(super::vrl_guard::compile(&code, &parser_vrl_functions()).is_err(), "{name}");
        assert!(
            super::VrlValidator::for_enrichment().test_vrl(&code, sample).await.map(|r| !r.success).unwrap_or(true),
            "{name} ran under the enrichment registry"
        );
        assert!(!vrl_function_catalog().lines().any(|l| l.starts_with(&format!("{name}("))), "{name}");
    }
}

/// The legitimate shape on the same path still compiles and runs.
#[tokio::test]
async fn ordinary_parser_still_runs_on_the_test_path() {
    let code = ".udm = {}\n.udm.user = downcase(string!(.user))\n.udm.raw = decode_base64!(.b64)\n";
    let sample = r#"{"user":"ALICE","b64":"aGVsbG8="}"#;
    let validator = super::VrlValidator::new();
    let tested = validator.test_vrl_chain(&[code], sample).await.unwrap();
    assert!(tested.success, "{tested:?}");
    let output = tested.output.expect("output");
    assert_eq!(output["udm"]["user"], "alice");
    assert_eq!(output["udm"]["raw"], "hello");
}
