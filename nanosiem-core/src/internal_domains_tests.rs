// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the open `internal_domains` matcher.

use super::*;

#[test]
fn label_boundary_matching() {
    let d = InternalDomains::with_suffixes(["prod", "corp.example.com"]);
    assert!(d.is_internal("prod"));
    assert!(d.is_internal("db1.prod"));
    assert!(d.is_internal("DB1.PROD."), "case and trailing dot");
    assert!(!d.is_internal("myprod.com"));
    assert!(!d.is_internal("db1.myprod"));
    assert!(!d.is_internal("prod.example.com"));
    assert!(d.is_internal("hr.corp.example.com"));
    assert!(!d.is_internal("evilcorp.example.com"));
    assert!(!d.is_internal(""));
    assert!(!d.is_internal("."));
    assert!(!d.is_internal("10.0.0.1"));
}

#[test]
fn builtins_always_apply() {
    let builtin = InternalDomains::builtin();
    assert!(builtin.is_internal("ws-legal-066.corp.local"));
    assert!(builtin.is_internal("x.arpa"));
    assert!(!builtin.is_internal("db1.prod"));
    assert_eq!(InternalDomains::with_suffixes(["local", "prod"]).tenant_suffixes(), ["prod"]);
}

#[test]
fn u_labels_and_a_labels_are_the_same_name() {
    assert_eq!(canonical_host("Bücher.Corp.").as_deref(), Some("xn--bcher-kva.corp"));
    // Suffix stored as an A-label, candidate as a U-label, and the reverse.
    let a = InternalDomains::with_suffixes(["xn--bcher-kva.example"]);
    assert!(a.is_internal("db.bücher.example"));
    assert!(a.is_internal("db.xn--bcher-kva.example"));
    let u = InternalDomains::with_suffixes(["bücher.example"]);
    assert_eq!(u.tenant_suffixes(), ["xn--bcher-kva.example"]);
    assert!(u.is_internal("DB.XN--BCHER-KVA.EXAMPLE"));
    assert!(!u.is_internal("db.bucher.example"));
}

#[test]
fn invalid_entries_are_dropped_not_matched() {
    let d = InternalDomains::with_suffixes(["", "a..b", "bad host", "-x.example", "ok.example", "10.0.0.1"]);
    assert_eq!(d.tenant_suffixes(), ["ok.example"]);
    assert_eq!(canonical_host(&"a".repeat(254)), None);
}

#[cfg(not(feature = "enterprise"))]
#[tokio::test]
async fn open_edition_effective_list_is_builtins_without_a_query() {
    // A lazy pool that cannot connect: a query would fail, the open seam never runs one.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    assert_eq!(*effective(&pool).await, InternalDomains::builtin());
}

#[test]
fn sql_predicate_lists_every_effective_suffix_in_canonical_form() {
    let sql = InternalDomains::with_suffixes(["Bücher.example", "a'b"]).sql_not_internal("dest_host");
    assert!(sql.starts_with("NOT arrayExists(s -> endsWith(concat('.', trimRight(tryIdnaEncode(lower(dest_host)), '.'))"));
    assert!(sql.contains("'local'") && sql.contains("'arpa'") && sql.contains("'xn--bcher-kva.example'"));
    assert!(!sql.contains("a'b"));
}
