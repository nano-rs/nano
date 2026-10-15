// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::query::parse_query;
use crate::search::query_processing::{
    enforce_source_scope, enforce_source_scope_with_field, LAKE_SOURCE_FIELD,
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn named(npl: &str, denied: &[&str]) -> BTreeSet<String> {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e:?}"));
    denied_sources_named(&parsed, &set(denied))
}

#[derive(Default)]
struct Capture(Mutex<Vec<DeniedSourceAuditRecord>>);

impl DeniedSourceAuditSink for Capture {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

impl Capture {
    fn take(&self) -> Vec<DeniedSourceAuditRecord> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

fn tenant(id: u128) -> TrustedTenantContext {
    TrustedTenantContext {
        tenant_id: Uuid::from_u128(id),
        tenant_slug: format!("t{id}"),
    }
}

fn scope(
    tenant_ctx: Option<TrustedTenantContext>,
    actor: Uuid,
    denied: &[&str],
    path: &str,
    sink: &Arc<Capture>,
    limiter: &Arc<DeniedSourceAuditLimiter>,
) -> Arc<DeniedSourceAuditScope> {
    Arc::new(
        DeniedSourceAuditScope::new(
            tenant_ctx,
            actor,
            None,
            &set(denied),
            path,
            Some("req-1"),
            ClientContext::default(),
            sink.clone() as Arc<dyn DeniedSourceAuditSink>,
        )
        .expect("restricted caller gets a scope")
        .with_limiter(limiter.clone()),
    )
}

fn fresh_limiter() -> Arc<DeniedSourceAuditLimiter> {
    Arc::new(DeniedSourceAuditLimiter::new(
        AUDIT_WINDOW,
        LIMITER_CAPACITY,
    ))
}

// ---------------------------------------------------------------- pure AST

#[test]
fn equality_on_either_source_field_names_the_label() {
    let denied = ["insider_threat", "hr_records"];
    assert_eq!(
        named("source_type=insider_threat", &denied),
        set(&["insider_threat"])
    );
    assert_eq!(
        named("metadata.log_source=\"insider_threat\" error", &denied),
        set(&["insider_threat"])
    );
    assert_eq!(
        named("SOURCE_TYPE=Insider_Threat", &denied),
        set(&["insider_threat"])
    );
}

#[test]
fn in_list_names_only_the_denied_members() {
    assert_eq!(
        named(
            "source_type IN (\"windows\", \"insider_threat\", \"hr_records\")",
            &["insider_threat", "hr_records", "payroll"]
        ),
        set(&["hr_records", "insider_threat"])
    );
}

#[test]
fn wildcards_like_and_regex_match_denied_labels() {
    let denied = ["insider_threat", "hr_records"];
    assert_eq!(
        named("source_type=insider*", &denied),
        set(&["insider_threat"])
    );
    assert_eq!(named("source_type=*records", &denied), set(&["hr_records"]));
    assert_eq!(
        named("source_type=/insid.*/", &denied),
        set(&["insider_threat"])
    );
}

#[test]
fn broad_searches_name_nothing() {
    let denied = ["insider_threat"];
    for npl in [
        "error",
        "insider_threat",
        "*",
        "source_type=*",
        "metadata.log_source=*",
        "user=insider_threat",
        "source_type=windows",
        "error | stats count by source_type",
    ] {
        assert!(named(npl, &denied).is_empty(), "{npl}");
    }
}

#[test]
fn negated_references_exclude_and_name_nothing() {
    let denied = ["insider_threat"];
    for npl in [
        "source_type!=insider_threat",
        "NOT source_type=insider_threat",
        "source_type NOT IN (\"insider_threat\")",
        "error NOT (source_type=insider_threat OR source_type=x)",
    ] {
        assert!(named(npl, &denied).is_empty(), "{npl}");
    }
    assert_eq!(
        named("NOT source_type!=insider_threat", &denied),
        set(&["insider_threat"])
    );
}

#[test]
fn subsearches_and_where_conditions_are_walked() {
    let denied = ["insider_threat", "hr_records"];
    assert_eq!(
        named("error | append [ source_type=insider_threat ]", &denied),
        set(&["insider_threat"])
    );
    assert_eq!(
        named("error | where source_type=\"hr_records\"", &denied),
        set(&["hr_records"])
    );
    assert_eq!(
        named(
            "error | join user [ search metadata.log_source=hr_records | fields user ]",
            &denied
        ),
        set(&["hr_records"])
    );
}

#[test]
fn lake_unattributed_spellings_fold_to_the_restriction_label() {
    let denied = crate::auth::source_visibility::expand_unattributed_sources(["default"]);
    let parsed = parse_query("metadata.log_source=unknown").unwrap();
    assert_eq!(denied_sources_named(&parsed, &denied), set(&["default"]));
}

#[test]
fn the_gates_own_injected_exclusion_is_not_a_reference() {
    let denied = set(&["insider_threat", "hr_records"]);
    let gated = enforce_source_scope("error | stats count", &denied).unwrap();
    assert!(
        denied_sources_named(&parse_query(&gated).unwrap(), &denied).is_empty(),
        "{gated}"
    );
    let gated = enforce_source_scope_with_field("error", &denied, LAKE_SOURCE_FIELD).unwrap();
    assert!(
        denied_sources_named(&parse_query(&gated).unwrap(), &denied).is_empty(),
        "{gated}"
    );
}

#[test]
fn raw_sql_names_quoted_denied_literals_only() {
    let denied = set(&["insider_threat", "hr_records"]);
    assert_eq!(
        raw_sql_named_denied_sources(
            "SELECT * FROM logs WHERE source_type = 'Insider_Threat'",
            &denied
        ),
        set(&["insider_threat"])
    );
    assert!(raw_sql_named_denied_sources("SELECT count() FROM logs", &denied).is_empty());
}

#[test]
fn entry_points_are_bounded_route_labels() {
    assert_eq!(entry_point_from_path("/api/search"), "search");
    assert_eq!(entry_point_from_path("/api/search/stream"), "search/stream");
    assert_eq!(
        entry_point_from_path("/api/search/field-values"),
        "search/field-values"
    );
    assert_eq!(
        entry_point_from_path("/api/search/saved/0192f0e4-8d7f-7c4e-9a8b-0123456789ab/run"),
        "search/saved/{id}/run"
    );
    assert_eq!(
        entry_point_from_path("/api/dashboards/42/panels/7/query"),
        "dashboards/{id}/panels/{id}/query"
    );
    assert!(entry_point_from_path(&format!("/api/{}", "a/".repeat(200))).len() <= 96);
}

// ---------------------------------------------------------------- limiter

#[test]
fn limiter_admits_once_per_window_per_key() {
    let limiter = DeniedSourceAuditLimiter::new(Duration::from_secs(300), 100);
    let actor = Uuid::from_u128(7);
    let t0 = Instant::now();
    assert!(limiter.admit(None, actor, "insider", "search", t0));
    assert!(!limiter.admit(
        None,
        actor,
        "insider",
        "search",
        t0 + Duration::from_secs(299)
    ));
    assert!(
        limiter.admit(None, actor, "insider", "search/stream", t0),
        "entry point is part of the key"
    );
    assert!(
        limiter.admit(None, actor, "hr", "search", t0),
        "label is part of the key"
    );
    assert!(
        limiter.admit(Some(Uuid::from_u128(1)), actor, "insider", "search", t0),
        "tenant is part of the key"
    );
    assert!(
        limiter.admit(
            None,
            actor,
            "insider",
            "search",
            t0 + Duration::from_secs(300)
        ),
        "window expired"
    );
}

#[test]
fn limiter_stays_bounded() {
    let limiter = DeniedSourceAuditLimiter::new(Duration::from_secs(300), 8);
    let t0 = Instant::now();
    for i in 0..1_000u128 {
        assert!(limiter.admit(None, Uuid::from_u128(i + 1), "insider", "search", t0));
        assert!(limiter.len() <= 8);
    }
}

// ---------------------------------------------------------------- request scope

#[tokio::test]
async fn named_denied_source_writes_one_audit_row() {
    let sink = Arc::new(Capture::default());
    let actor = Uuid::from_u128(11);
    let s = scope(
        Some(tenant(1)),
        actor,
        &["insider_threat", "hr_records", "payroll"],
        "/api/search",
        &sink,
        &fresh_limiter(),
    );
    with_scope(s, async {
        enforce_source_scope_with_field(
            "metadata.log_source=insider_threat | stats count",
            &set(&["insider_threat", "hr_records", "payroll"]),
            LAKE_SOURCE_FIELD,
        )
        .unwrap();
    })
    .await;
    let rows = sink.take();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row.labels,
        vec!["insider_threat".to_string()],
        "only the named label, never the deny set"
    );
    assert_eq!(row.outcome, DeniedSourceOutcome::Filtered);
    assert_eq!(row.entry_point, "search");
    assert_eq!(row.request_id.as_deref(), Some("req-1"));
    assert_eq!(row.actor_id, actor);
    assert_eq!(
        row.tenant.as_ref().map(|t| t.tenant_id),
        Some(Uuid::from_u128(1))
    );
    let event = row.to_audit_event();
    assert_eq!(event.action, "search.source_scope_denied");
    assert_eq!(event.source, AuditSource::Search);
    assert!(!event.success);
    let details = event.details.unwrap();
    assert_eq!(details["outcome"], "filtered");
    assert_eq!(details["denied_sources"], json!(["insider_threat"]));
    assert_eq!(
        details["query"],
        "metadata.log_source=insider_threat | stats count"
    );
    assert!(
        !details.to_string().contains("payroll"),
        "the full deny set must never be written"
    );
}

#[tokio::test]
async fn broad_search_writes_no_audit_row() {
    let sink = Arc::new(Capture::default());
    let s = scope(
        None,
        Uuid::from_u128(12),
        &["insider_threat"],
        "/api/search",
        &sink,
        &fresh_limiter(),
    );
    with_scope(s, async {
        for npl in [
            "error",
            "* | stats count by source_type",
            "source_type=windows",
        ] {
            enforce_source_scope(npl, &set(&["insider_threat"])).unwrap();
        }
    })
    .await;
    assert!(sink.take().is_empty());
}

#[tokio::test]
async fn rate_limit_holds_across_repeats_and_reopens_per_entry_point() {
    let sink = Arc::new(Capture::default());
    let limiter = fresh_limiter();
    let actor = Uuid::from_u128(13);
    let deny = set(&["insider_threat"]);
    for _ in 0..5 {
        let s = scope(
            None,
            actor,
            &["insider_threat"],
            "/api/search",
            &sink,
            &limiter,
        );
        with_scope(s, async {
            enforce_source_scope("source_type=insider_threat", &deny).unwrap()
        })
        .await;
    }
    assert_eq!(
        sink.take().len(),
        1,
        "dashboards / live tail must not flood"
    );
    let s = scope(
        None,
        actor,
        &["insider_threat"],
        "/api/search/histogram",
        &sink,
        &limiter,
    );
    with_scope(s, async {
        enforce_source_scope("source_type=insider_threat", &deny).unwrap()
    })
    .await;
    assert_eq!(sink.take().len(), 1, "a new entry point is a new key");
}

#[tokio::test]
async fn no_cross_tenant_leak() {
    let sink_a = Arc::new(Capture::default());
    let sink_b = Arc::new(Capture::default());
    let limiter = fresh_limiter();
    let actor = Uuid::from_u128(14);
    let a = scope(
        Some(tenant(1)),
        actor,
        &["insider_threat"],
        "/api/search",
        &sink_a,
        &limiter,
    );
    let b = scope(
        Some(tenant(2)),
        actor,
        &["payroll"],
        "/api/search",
        &sink_b,
        &limiter,
    );
    // Tenant B's member names tenant A's hidden label: B does not deny it, so
    // nothing is withheld and nothing is audited — and A's set never leaks.
    with_scope(b.clone(), async {
        enforce_source_scope_with_field(
            "metadata.log_source=insider_threat",
            &set(&["payroll"]),
            LAKE_SOURCE_FIELD,
        )
        .unwrap();
    })
    .await;
    assert!(sink_b.take().is_empty());
    with_scope(a, async {
        enforce_source_scope_with_field(
            "metadata.log_source=insider_threat",
            &set(&["insider_threat"]),
            LAKE_SOURCE_FIELD,
        )
        .unwrap();
    })
    .await;
    with_scope(b, async {
        enforce_source_scope_with_field(
            "metadata.log_source=payroll",
            &set(&["payroll"]),
            LAKE_SOURCE_FIELD,
        )
        .unwrap();
    })
    .await;
    let rows_a = sink_a.take();
    let rows_b = sink_b.take();
    assert_eq!(rows_a.len(), 1);
    assert_eq!(
        rows_b.len(),
        1,
        "tenant A's audit must not rate-limit tenant B"
    );
    assert_eq!(
        rows_a[0].tenant.as_ref().unwrap().tenant_id,
        Uuid::from_u128(1)
    );
    assert_eq!(rows_a[0].labels, vec!["insider_threat".to_string()]);
    assert_eq!(
        rows_b[0].tenant.as_ref().unwrap().tenant_id,
        Uuid::from_u128(2)
    );
    assert_eq!(rows_b[0].labels, vec!["payroll".to_string()]);
}

#[tokio::test]
async fn user_visible_rewrite_is_byte_identical_with_and_without_auditing() {
    let deny = set(&["insider_threat", "hr_records"]);
    for (npl, field) in [
        (
            "source_type=insider_threat earliest=-1h | stats count by host",
            "source_type",
        ),
        (
            "metadata.log_source=insider_threat | head 10",
            LAKE_SOURCE_FIELD,
        ),
        (
            "error | append [ metadata.log_source=hr_records ]",
            LAKE_SOURCE_FIELD,
        ),
        ("error", LAKE_SOURCE_FIELD),
    ] {
        let without = enforce_source_scope_with_field(npl, &deny, field).unwrap();
        let sink = Arc::new(Capture::default());
        let s = scope(
            None,
            Uuid::from_u128(15),
            &["insider_threat", "hr_records"],
            "/api/search",
            &sink,
            &fresh_limiter(),
        );
        let with = with_scope(s, async {
            enforce_source_scope_with_field(npl, &deny, field).unwrap()
        })
        .await;
        assert_eq!(with, without, "{npl}");
    }
}

#[tokio::test]
async fn raw_sql_refusal_is_audited_as_refused() {
    let sink = Arc::new(Capture::default());
    let s = scope(
        None,
        Uuid::from_u128(16),
        &["insider_threat"],
        "/api/search/sql",
        &sink,
        &fresh_limiter(),
    );
    with_scope(s, async {
        observe_raw_sql_refused("SELECT * FROM logs WHERE source_type='insider_threat'");
        observe_raw_sql_refused("SELECT * FROM logs WHERE source_type='insider_threat'");
        observe_raw_sql_refused("SELECT count() FROM logs");
    })
    .await;
    let rows = sink.take();
    assert_eq!(
        rows.len(),
        2,
        "one per label key (rate limited), one for the unnamed refusal"
    );
    assert_eq!(rows[0].outcome, DeniedSourceOutcome::Refused);
    assert_eq!(rows[0].labels, vec!["insider_threat".to_string()]);
    assert_eq!(rows[0].entry_point, "search/sql");
    assert!(rows[1].labels.is_empty());
    assert_eq!(
        rows[1].to_audit_event().details.unwrap()["outcome"],
        "refused"
    );
}

#[tokio::test]
async fn unrestricted_callers_get_no_scope_and_hooks_are_inert_outside_one() {
    let sink: Arc<dyn DeniedSourceAuditSink> = Arc::new(Capture::default());
    assert!(DeniedSourceAuditScope::new(
        None,
        Uuid::from_u128(1),
        None,
        &BTreeSet::new(),
        "/api/search",
        None,
        ClientContext::default(),
        sink.clone()
    )
    .is_none());
    assert!(DeniedSourceAuditScope::new(
        None,
        Uuid::nil(),
        None,
        &set(&["x"]),
        "/api/search",
        None,
        ClientContext::default(),
        sink
    )
    .is_none());
    // No scope installed: the gate still works and nothing panics.
    enforce_source_scope("source_type=insider_threat", &set(&["insider_threat"])).unwrap();
    observe_raw_sql_refused("SELECT 1");
}

#[tokio::test]
async fn spawned_search_work_inherits_the_scope_only_through_inherit() {
    let sink = Arc::new(Capture::default());
    let s = scope(
        None,
        Uuid::from_u128(17),
        &["insider_threat"],
        "/api/search/stream",
        &sink,
        &fresh_limiter(),
    );
    with_scope(s, async {
        tokio::spawn(async {
            enforce_source_scope("source_type=insider_threat", &set(&["insider_threat"])).unwrap()
        })
        .await
        .unwrap();
        assert!(current().is_some());
    })
    .await;
    assert!(
        sink.take().is_empty(),
        "a bare spawn does not carry the scope"
    );
    let s = scope(
        None,
        Uuid::from_u128(17),
        &["insider_threat"],
        "/api/search/stream",
        &sink,
        &fresh_limiter(),
    );
    with_scope(s, async {
        tokio::spawn(crate::search::request_actor::inherit(async {
            enforce_source_scope("source_type=insider_threat", &set(&["insider_threat"])).unwrap()
        }))
        .await
        .unwrap();
    })
    .await;
    assert_eq!(sink.take().len(), 1);
}
