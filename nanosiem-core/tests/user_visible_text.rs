// SPDX-License-Identifier: AGPL-3.0-or-later

use regex::Regex;

#[test]
fn user_facing_errors_and_display_literals_have_no_internal_ticket_ids() {
    let ticket = Regex::new(r"\b(?:NAN|FOR)-?\d+\b").unwrap();
    // Scan display/error source literals, excluding comments, tracing and test modules.
    // Internal audit metadata is not a display message; its protocol issue key is excluded.
    struct DisplayStrings<'a> { ticket: &'a Regex, path: &'a str }
    impl<'ast> syn::visit::Visit<'ast> for DisplayStrings<'_> {
        fn visit_attribute(&mut self, _: &'ast syn::Attribute) {} // Documentation is checked by OpenAPI.
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if node.attrs.iter().any(|a| a.path().is_ident("cfg") && matches!(&a.meta, syn::Meta::List(list) if list.tokens.to_string().contains("test"))) { return; }
            syn::visit::visit_item_mod(self, node);
        }
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            assert!(!self.ticket.is_match(&literal.value()), "internal tracker in {}", self.path);
        }
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            let name = node.path.segments.last().unwrap().ident.to_string();
            if ["info", "warn", "error", "debug", "trace"].contains(&name.as_str()) { return; }
            // syn does not visit macro arguments, so inspect each literal token recursively.
            fn literals(tokens: proc_macro2::TokenStream, visitor: &mut DisplayStrings<'_>) {
                for token in tokens {
                    match token {
                        proc_macro2::TokenTree::Group(group) => literals(group.stream(), visitor),
                        proc_macro2::TokenTree::Literal(lit) => {
                            if let Ok(value) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                                syn::visit::Visit::visit_lit_str(visitor, &value);
                            }
                        }
                        _ => {}
                    }
                }
            }
            literals(node.tokens.clone(), self);
        }
    }
    use syn::visit::Visit;
    for (path, source) in [
        ("runtime profile", include_str!("../src/schema/runtime_profile.rs")),
        ("parser diagnostics", include_str!("../src/query/parser/error.rs")),
        ("parser validation", include_str!("../src/parsers/service/crud.rs")),
        ("parser repository", include_str!("../src/parser_repository/service.rs")),
        ("rule repository", include_str!("../src/rule_repository/service/import.rs")),
        #[cfg(feature = "enterprise")]
        ("playbook repository", include_str!("../src/playbook_repository/service/import.rs")),
    ] {
        DisplayStrings { ticket: &ticket, path }.visit_file(&syn::parse_file(source).unwrap());
    }

}

#[cfg(feature = "enterprise")]
#[test]
fn system_worker_migration_display_text_has_no_tracker_reference() {
    let sql = include_str!("../../migrations/postgres-enterprise/9013470_system_worker_display_description.sql");
    let display = Regex::new(r"description\s*=\s*'([^']*)'").unwrap();
    let ticket = Regex::new(r"\b(?:NAN|FOR)-?\d+\b").unwrap();
    let rows = display.captures_iter(sql).collect::<Vec<_>>();
    assert!(!rows.is_empty());
    for row in rows { assert!(!ticket.is_match(&row[1])); }
    assert!(sql.contains("AND tenant_id IS NULL AND is_system"));
    assert!(!sql.contains("UPDATE public.role_permissions"));
}

#[test]
fn migration_display_seeds_have_no_internal_ticket_ids() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let seeded = Regex::new(r"(?is)\b(?:INSERT\s+INTO|UPDATE)\s+(?:public\.)?(?:roles|users|permissions|dashboards|rules)\b[^;]*;").unwrap();
    let ticket = Regex::new(r"\b(?:NAN|FOR)-?\d+\b").unwrap();
    for dir in ["migrations/postgres", "migrations/postgres-open", "migrations/postgres-enterprise"] {
        if dir == "migrations/postgres-enterprise" && !cfg!(feature = "enterprise") { continue; }
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("sql") { continue; }
            // Immutable historical seed; 9013470 replaces its display description on all installs.
            if path.file_name().unwrap() == "9001040_enterprise_shared_runtime_assignments_control.sql" { continue; }
            let sql = std::fs::read_to_string(&path).unwrap();
            let sql = sql.lines().filter(|line| !line.trim_start().starts_with("--")).collect::<Vec<_>>().join("\n");
            for statement in seeded.find_iter(&sql) {
                assert!(!ticket.is_match(statement.as_str()), "internal tracker in display seed {}", path.display());
            }
        }
    }
}
