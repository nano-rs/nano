//! NAN-4914: the open engine carries no SOAR surface. Collector and lookup
//! specs see only the built-in template namespaces (no `steps`, `poll`,
//! `run`, `alert` or `case`), and there is no private-network scope (see
//! tests/shared_ssrf.rs). SOAR's request sequences live in
//! nanosiem-enterprise::soar_engine.

use nano_connector::engine::{compile, compile_with_namespaces, default_ceilings, EngineError};
use nano_connector::spec::ConnectorSpec;
use nano_connector::template::{references, render_str, Scope, TemplateError};
use serde_json::json;

fn spec_with_url(url: &str) -> ConnectorSpec {
    serde_json::from_value(json!({
        "version": 1, "name": "t", "kind": "collector",
        "allow": [{"host": "api.example.com"}],
        "streams": [{"id": "s", "request": {"url": url}}]
    }))
    .unwrap()
}

#[test]
fn collectors_cannot_reference_soar_namespaces() {
    for ns in ["steps", "poll", "run", "alert", "case"] {
        let url = format!("https://api.example.com/v1/{{{{{ns}.id}}}}");
        let err = compile(&spec_with_url(&url), &default_ceilings()).err().expect(ns);
        assert!(matches!(err, EngineError::Template(TemplateError::Unknown(_))), "{ns}: {err}");
        assert!(matches!(references(&format!("{{{{{ns}.x}}}}")), Err(TemplateError::Unknown(_))), "{ns}");
    }
    // Built-ins still work.
    assert!(compile(&spec_with_url("https://api.example.com/v1/{{config.ID}}"), &default_ceilings()).is_ok());
}

#[test]
fn host_namespaces_are_opt_in_and_never_override_forbidden_or_built_ins() {
    // An embedding host admits its own namespaces explicitly.
    assert!(compile_with_namespaces(&spec_with_url("https://api.example.com/v1/{{steps.read.id}}"), &default_ceilings(), &["steps"]).is_ok());
    // A host namespace cannot unlock a forbidden one.
    assert!(matches!(
        compile_with_namespaces(&spec_with_url("https://api.example.com/{{credentials.X}}"), &default_ceilings(), &["credentials"]).err(),
        Some(EngineError::Template(TemplateError::Forbidden(_)))
    ));
    // Rendering admits only the namespaces the scope carries.
    let mut scope = Scope { config: json!({"ID": "c"}), ..Default::default() };
    assert!(render_str("{{alert.id}}", &scope).is_err());
    scope.host.insert("alert".into(), json!({"id": "a1"}));
    assert_eq!(render_str("{{alert.id}}", &scope).unwrap(), "a1");
    // A host value named like a built-in never shadows it.
    scope.host.insert("config".into(), json!({"ID": "shadow"}));
    assert_eq!(render_str("{{config.ID}}", &scope).unwrap(), "c");
    scope.host.insert("secrets".into(), json!({"X": "leak"}));
    assert!(matches!(render_str("{{secrets.X}}", &scope), Err(TemplateError::Forbidden(_))));
}
