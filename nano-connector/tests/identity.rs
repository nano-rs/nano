// SPDX-License-Identifier: AGPL-3.0-or-later

//! G22 (port of NAN-3503): `kind: identity` end to end on the ClickHouse
//! product. The bundled `okta_users` and `entra_directory` specs run through
//! the real engine, egress broker and sandboxed VRL workers against TLS mock
//! vendors, delivering into an in-memory directory with the same merge rules
//! as the ClickHouse `user_registry` writer.
//!
//! Proves:
//! - full run: users upserted, managers resolved, memberships applied, the
//!   checkpoint (cursor, last full time, user count) saved only after the
//!   snapshot committed;
//! - delta run: a patch changes only what it sends, Okta DEPROVISIONED maps
//!   to disabled, Entra `@removed` tombstones, one checkpoint per page;
//! - Graph 410 / `syncStateNotFound` reruns the stream as a full run;
//! - a later full run retires users it no longer returns; the shrink guard
//!   refuses a run that would drop more than half the directory (nothing
//!   retired, no checkpoint), and `identity_allow_shrink` lets it through;
//! - spec shape rules and identity limits;
//! - the runner runs identity feeds into its directory and fails them
//!   clearly when it has none.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use nano_connector::engine::{self, MemoryStore, RunInput, RunOutput};
use nano_connector::identity::{
    Directory, FencedWrite, IdentitySink, IdentityTarget, MemoryDirectory, ShrinkGuard, WriteFence, account_status, clean_text,
    normalize_user,
};
use nano_connector::service::directory::MemoryDirectories;
use nano_connector::service::feed::spec_sha256;
use nano_connector::service::{FeedDefinition, MemoryFeedStore, RunStatus, Runner, RunnerConfig, Secret, StaticIngest};
use nano_connector::spec::{ConnectorSpec, IdentityMode};
use serde_json::{Value, json};
use uuid::Uuid;

const OKTA_SPEC: &str = include_str!("../specs/okta_users.yaml");
const ENTRA_SPEC: &str = include_str!("../specs/entra_directory.yaml");
const OKTA_TOKEN: &str = "okta-api-token-abcdef0123456789";
const DIRECTORY: &str = "e6800ccd-d972-42ce-b555-dbf0a25ed9a7";
const CLIENT: &str = "5e30aef4-9c37-4841-997d-0324ff914452";
const CLIENT_SECRET: &str = "entra-client-secret-0123456789abcdef";

// ------------------------------------------------------------ Okta vendor

#[derive(Clone)]
struct OktaUser {
    id: &'static str,
    login: &'static str,
    status: &'static str,
    title: &'static str,
    manager: &'static str,
    updated: &'static str,
}

#[derive(Default)]
struct OktaState {
    full: Vec<OktaUser>,
    delta: Vec<OktaUser>,
    groups: Vec<(&'static str, &'static str, Vec<&'static str>)>,
}

fn okta_json(u: &OktaUser) -> Value {
    json!({
        "id": u.id, "status": u.status, "lastUpdated": u.updated,
        "created": "2024-01-01T00:00:00.000Z", "lastLogin": "2026-10-01T08:00:00.000Z",
        "profile": {
            "login": u.login, "email": u.login, "firstName": u.id, "lastName": "Test",
            "title": u.title, "department": "Eng", "managerId": u.manager,
        }
    })
}

fn okta_vendor(st: Arc<Mutex<OktaState>>) -> Handler {
    Arc::new(move |r: &MockReq| {
        let st = st.lock().unwrap();
        if r.headers.get("authorization").map(String::as_str) != Some(&format!("SSWS {OKTA_TOKEN}")) {
            return MockResp::status(401, json!({"errorSummary": "bad token"}));
        }
        match r.path.as_str() {
            "/api/v1/users" => {
                let search = r.query.get("search").cloned().unwrap_or_default();
                let users = if search.starts_with("lastUpdated gt") { &st.delta } else { &st.full };
                // Two per page, Link-paged.
                let after: usize = r.query.get("after").and_then(|a| a.parse().ok()).unwrap_or(0);
                let page: Vec<Value> = users.iter().skip(after).take(2).map(okta_json).collect();
                let mut resp = MockResp::json(Value::Array(page));
                if after + 2 < users.len() {
                    let next = url::Url::parse_with_params(
                        "https://acme.okta.com/api/v1/users",
                        &[("limit", "200"), ("search", search.as_str()), ("after", &(after + 2).to_string())],
                    )
                    .unwrap();
                    resp = resp.header("link", &format!("<{next}>; rel=\"next\""));
                }
                resp
            }
            "/api/v1/groups" => MockResp::json(Value::Array(
                st.groups.iter().map(|(id, name, _)| json!({"id": id, "profile": {"name": name}})).collect(),
            )),
            "/api/v1/iam/assignees/users" => MockResp::json(json!({"value": []})),
            p if p.starts_with("/api/v1/groups/") && p.ends_with("/users") => {
                let gid = p.trim_start_matches("/api/v1/groups/").trim_end_matches("/users");
                let members = st.groups.iter().find(|(id, _, _)| *id == gid).map(|(_, _, m)| m.clone()).unwrap_or_default();
                MockResp::json(Value::Array(members.iter().map(|m| json!({"id": m})).collect()))
            }
            _ => MockResp::status(404, json!({"errorSummary": "not found"})),
        }
    })
}

fn u(id: &'static str, status: &'static str, title: &'static str, manager: &'static str) -> OktaUser {
    let login = Box::leak(format!("{id}@acme.example").into_boxed_str());
    OktaUser { id, login, status, title, manager, updated: "2026-11-01T10:00:00.000Z" }
}

fn okta_input(checkpoints: HashMap<String, Value>, allow_shrink: bool) -> RunInput {
    let mut cfg = json!({"OKTA_DOMAIN": "acme.okta.com"});
    if allow_shrink {
        cfg["identity_allow_shrink"] = json!(true);
    }
    RunInput {
        config: config(cfg),
        credentials: creds(&[("API_TOKEN", OKTA_TOKEN)]),
        checkpoints,
        ..Default::default()
    }
}

struct IdRun {
    out: Result<RunOutput, engine::EngineError>,
    store: Arc<MemoryStore>,
}

impl IdRun {
    /// The last checkpoint saved per stream.
    fn checkpoints(&self) -> HashMap<String, Value> {
        let mut out = HashMap::new();
        for (s, v) in self.store.saves.lock().unwrap().iter() {
            out.insert(s.clone(), v.clone());
        }
        out
    }
    fn saves_for(&self, stream: &str) -> usize {
        self.store.saves.lock().unwrap().iter().filter(|(s, _)| s == stream).count()
    }
}

async fn run_identity(h: &Harness, spec: &ConnectorSpec, input: RunInput, dir: &Arc<MemoryDirectory>) -> IdRun {
    // A loaded CI host can take longer than the spec's 2 s VRL budget for
    // the first (cold) compile; the budget is not what these tests prove.
    let mut spec = spec.clone();
    spec.limits.vrl_timeout_ms = 10_000;
    let spec = &spec;
    let sink = Arc::new(IdentitySink::new(dir.clone(), 5_000_000));
    let store = Arc::new(MemoryStore::default());
    let out = engine::run(&h.cfg, spec, input, sink, store.clone()).await;
    IdRun { out, store }
}

fn ok(r: &IdRun) -> &RunOutput {
    r.out.as_ref().unwrap_or_else(|e| panic!("run failed: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn okta_full_delta_and_a_shrinking_full_run() {
    let st = Arc::new(Mutex::new(OktaState {
        full: vec![
            u("00u1", "ACTIVE", "CEO", ""),
            u("00u2", "ACTIVE", "SRE", "00u1@acme.example"),
            u("00u3", "SUSPENDED", "Dev", ""),
            u("00u4", "ACTIVE", "Ops", ""),
        ],
        delta: vec![],
        groups: vec![("g1", "Admins", vec!["00u1", "00u2"]), ("g2", "Everyone", vec!["00u1", "00u2", "00u3", "00u4", "00uX"])],
    }));
    let mock = start_mock(okta_vendor(st.clone()), false).await;
    let h = harness(&mock);
    let spec = spec(OKTA_SPEC);
    let dir = Arc::new(MemoryDirectory::default());

    // 1. First run: no cursor, so full.
    let r1 = run_identity(&h, &spec, okta_input(HashMap::new(), false), &dir).await;
    assert_eq!(ok(&r1).identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    let mut live = dir.live();
    live.sort();
    assert_eq!(live, ["00u1", "00u2", "00u3", "00u4"]);
    let u2 = dir.get("00u2").unwrap();
    assert_eq!(u2.upn.as_deref(), Some("00u2@acme.example"));
    assert_eq!(u2.title.as_deref(), Some("SRE"));
    assert_eq!(u2.manager_upn.as_deref(), Some("00u1@acme.example"));
    assert_eq!(u2.account_status, "active");
    assert!(u2.account_enabled);
    assert_eq!(u2.groups, vec!["Admins".to_string(), "Everyone".to_string()]);
    assert_eq!(dir.get("00u3").unwrap().account_status, "suspended");
    assert_eq!(dir.get("00u4").unwrap().groups, vec!["Everyone".to_string()]);
    // A full run saves exactly one users checkpoint, after the commit.
    assert_eq!(r1.saves_for("users"), 1);
    let cp = r1.checkpoints();
    assert_eq!(cp["users"]["identity_last_full_rows"], 4);
    assert!(cp["users"]["identity_last_full_at"].is_string());
    assert_eq!(cp["users"]["state"]["last_updated"], "2026-11-01T10:00:00.000Z");
    // Memberships save no checkpoint.
    assert_eq!(r1.saves_for("groups"), 0);

    // 2. Delta: one change (title) and one deprovision.
    {
        let mut s = st.lock().unwrap();
        let mut changed = u("00u2", "ACTIVE", "Staff SRE", "00u1@acme.example");
        changed.updated = "2026-11-02T10:00:00.000Z";
        let mut gone = u("00u4", "DEPROVISIONED", "Ops", "");
        gone.updated = "2026-11-02T11:00:00.000Z";
        s.delta = vec![changed, gone];
    }
    let r2 = run_identity(&h, &spec, okta_input(cp.clone(), false), &dir).await;
    assert_eq!(ok(&r2).identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
    let u2 = dir.get("00u2").unwrap();
    assert_eq!(u2.title.as_deref(), Some("Staff SRE"));
    assert_eq!(u2.groups, vec!["Admins".to_string(), "Everyone".to_string()], "a delta keeps memberships");
    let u4 = dir.get("00u4").unwrap();
    assert_eq!(u4.account_status, "disabled");
    assert!(!u4.account_enabled);
    let cp2 = r2.checkpoints();
    assert_eq!(cp2["users"]["state"]["last_updated"], "2026-11-02T11:00:00.000Z");
    // A delta keeps the last full run's time and count (the shrink guard).
    assert_eq!(cp2["users"]["identity_last_full_rows"], 4);
    // The delta search asked from the cursor minus the 5-minute overlap.
    let searched: Vec<String> = mock
        .requests()
        .iter()
        .filter(|r| r.path == "/api/v1/users")
        .filter_map(|r| r.query.get("search").cloned())
        .filter(|s| s.starts_with("lastUpdated"))
        .collect();
    assert_eq!(searched[0], "lastUpdated gt \"2026-11-01T09:55:00.000Z\"");

    // 3. A forced full run (no delta cursor) that no longer returns 00u3.
    st.lock().unwrap().full.retain(|u| u.id != "00u3");
    let r3 = run_identity(&h, &spec, okta_input(HashMap::new(), false), &dir).await;
    ok(&r3);
    assert_eq!(dir.get("00u3").unwrap().account_status, "deleted", "a full run retires users it did not return");
    assert_eq!(r3.checkpoints()["users"]["identity_last_full_rows"], 3);

    // 4. A full run with 1 of the previous 3: refused, nothing retired, no
    //    users checkpoint.
    st.lock().unwrap().full.truncate(1);
    // The saved cursor is fresh (a delta would run), so force a full run by
    // dropping the cursor state; the last full count stays for the guard.
    let mut forced = r3.checkpoints();
    forced.get_mut("users").unwrap().as_object_mut().unwrap().remove("state");
    let r5 = run_identity(&h, &spec, okta_input(forced.clone(), false), &dir).await;
    let err = r5.out.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("identity_shrink_refused"), "{err}");
    assert_eq!(r5.saves_for("users"), 0);
    assert_eq!(dir.get("00u2").unwrap().account_status, "active", "nothing retired by a refused run");

    // 5. The operator allows the shrink.
    let r6 = run_identity(&h, &spec, okta_input(forced, true), &dir).await;
    ok(&r6);
    assert_eq!(dir.get("00u2").unwrap().account_status, "deleted");
    assert_eq!(dir.live(), ["00u1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_full_run_never_wipes_the_directory() {
    let st = Arc::new(Mutex::new(OktaState { full: vec![u("00u1", "ACTIVE", "CEO", "")], ..Default::default() }));
    let mock = start_mock(okta_vendor(st.clone()), false).await;
    let h = harness(&mock);
    let spec = spec(OKTA_SPEC);
    let dir = Arc::new(MemoryDirectory::default());
    ok(&run_identity(&h, &spec, okta_input(HashMap::new(), false), &dir).await);
    st.lock().unwrap().full.clear();
    let r = run_identity(&h, &spec, okta_input(HashMap::new(), false), &dir).await;
    let err = r.out.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("returned no users"), "{err}");
    assert_eq!(dir.live(), ["00u1"]);
    // No memberships at all keeps the stored groups (and is not an error).
    assert!(dir.get("00u1").unwrap().groups.is_empty());
}

// ------------------------------------------------------------ Entra vendor

#[derive(Default)]
struct GraphState {
    users: Vec<Value>,
    delta: Vec<Value>,
    gone: bool,
}

fn graph_vendor(st: Arc<Mutex<GraphState>>) -> Handler {
    Arc::new(move |r: &MockReq| {
        let st = st.lock().unwrap();
        if r.host == "login.microsoftonline.com" {
            assert_eq!(r.path, format!("/{DIRECTORY}/oauth2/v2.0/token"));
            return MockResp::json(json!({"access_token": "graph-access-token-0123456789", "token_type": "Bearer", "expires_in": 3600}));
        }
        if r.headers.get("authorization").map(String::as_str) != Some("Bearer graph-access-token-0123456789") {
            return MockResp::status(401, json!({"error": {"code": "InvalidAuthenticationToken", "message": "no"}}));
        }
        match r.path.as_str() {
            "/v1.0/users/delta" => {
                let token = r.query.get("$deltatoken").cloned().unwrap_or_default();
                if token == "latest" {
                    return MockResp::json(json!({"value": [], "@odata.deltaLink": "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=D1"}));
                }
                if st.gone {
                    return MockResp::status(410, json!({"error": {"code": "syncStateNotFound", "message": "gone"}}));
                }
                MockResp::json(json!({"value": st.delta, "@odata.deltaLink": "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=D2"}))
            }
            "/v1.0/users" => MockResp::json(json!({"value": st.users})),
            "/v1.0/groups" => MockResp::json(json!({"value": [{"id": "g1", "displayName": "Admins"}]})),
            "/v1.0/groups/g1/transitiveMembers/microsoft.graph.user" => MockResp::json(json!({"value": [{"id": "e1"}]})),
            "/v1.0/directoryRoles" => MockResp::json(json!({"value": [{"id": "r1", "displayName": "Global Administrator"}]})),
            "/v1.0/directoryRoles/r1/members" => {
                MockResp::json(json!({"value": [{"id": "e2", "@odata.type": "#microsoft.graph.user"}]}))
            }
            _ => MockResp::status(404, json!({"error": {"code": "NotFound", "message": r.path}})),
        }
    })
}

fn graph_user(id: &str, upn: &str, title: &str, manager: Option<(&str, &str)>) -> Value {
    let mut v = json!({
        "id": id, "userPrincipalName": upn, "mail": upn, "displayName": id, "givenName": id, "surname": "T",
        "jobTitle": title, "accountEnabled": true, "createdDateTime": "2024-01-01T00:00:00Z", "userType": "Member",
    });
    if let Some((mid, mupn)) = manager {
        v["manager"] = json!({"id": mid, "userPrincipalName": mupn, "displayName": mid});
    }
    v
}

fn entra_input(checkpoints: HashMap<String, Value>) -> RunInput {
    RunInput {
        config: config(json!({"DIRECTORY_ID": DIRECTORY, "CLIENT_ID": CLIENT})),
        credentials: creds(&[("CLIENT_SECRET", CLIENT_SECRET)]),
        checkpoints,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entra_full_delta_tombstones_managers_by_id_and_410_restarts_full() {
    let st = Arc::new(Mutex::new(GraphState {
        users: vec![
            graph_user("e1", "boss@contoso.example", "CEO", None),
            graph_user("e2", "ann@contoso.example", "SRE", Some(("e1", "boss@contoso.example"))),
            graph_user("e3", "bob@contoso.example", "Dev", None),
        ],
        ..Default::default()
    }));
    let mock = start_mock(graph_vendor(st.clone()), false).await;
    let h = harness(&mock);
    let spec = spec(ENTRA_SPEC);
    let dir = Arc::new(MemoryDirectory::default());

    let r1 = run_identity(&h, &spec, entra_input(HashMap::new()), &dir).await;
    assert_eq!(ok(&r1).identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    assert_eq!(dir.get("e2").unwrap().manager_upn.as_deref(), Some("boss@contoso.example"));
    assert_eq!(dir.get("e1").unwrap().groups, vec!["Admins".to_string()]);
    assert_eq!(dir.get("e2").unwrap().groups, vec!["role:Global Administrator".to_string()]);
    let cp = r1.checkpoints();
    assert_eq!(cp["users"]["state"]["delta_link"], "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=D1");

    // Delta: e3 moves under e1 (manager@delta, id only), e2 is removed.
    st.lock().unwrap().delta = vec![
        json!({"id": "e3", "jobTitle": "Lead", "manager@delta": [{"id": "e1"}]}),
        json!({"id": "e2", "@removed": {"reason": "deleted"}}),
    ];
    let r2 = run_identity(&h, &spec, entra_input(cp), &dir).await;
    assert_eq!(ok(&r2).identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
    let e3 = dir.get("e3").unwrap();
    assert_eq!(e3.title.as_deref(), Some("Lead"));
    assert_eq!(e3.upn.as_deref(), Some("bob@contoso.example"), "a Graph delta is a patch");
    assert_eq!(e3.manager_upn.as_deref(), Some("boss@contoso.example"), "manager resolved from the directory");
    assert_eq!(e3.account_status, "active", "a delta without accountEnabled keeps the status");
    assert!(e3.account_enabled);
    assert_eq!(dir.get("e2").unwrap().account_status, "deleted");
    let cp2 = r2.checkpoints();
    assert_eq!(cp2["users"]["state"]["delta_link"], "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=D2");

    // The delta token expired: the stream reruns full in the same run.
    st.lock().unwrap().gone = true;
    let r3 = run_identity(&h, &spec, entra_input(cp2), &dir).await;
    assert_eq!(ok(&r3).identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    // The full list still returns e2: it is live again.
    assert_eq!(dir.get("e2").unwrap().account_status, "active");
    assert_eq!(r3.checkpoints()["users"]["identity_last_full_rows"], 3);
}

// ------------------------------------------------------------ shape, limits, units

#[test]
fn identity_spec_shape_is_validated() {
    let base = |streams: &str, extra: &str| {
        format!(
            "version: 1\nname: t\nkind: identity\nallow: [{{host: api.example.com}}]\n{extra}streams:\n{streams}"
        )
    };
    let compile = |y: &str| engine::compile(&ConnectorSpec::from_yaml(y).unwrap(), &engine::default_ceilings()).map(|_| ());
    let ok_users = "  - id: users\n    identity: {role: users, mode: delta}\n    request: {url: \"https://api.example.com/u\"}\n";
    assert!(compile(&base(ok_users, "")).is_ok());
    // Every stream needs a role.
    let no_role = "  - id: users\n    request: {url: \"https://api.example.com/u\"}\n";
    assert!(compile(&base(no_role, "")).unwrap_err().to_string().contains("needs `identity"));
    // The users stream is `users`.
    let wrong_id = "  - id: people\n    identity: {role: users}\n    request: {url: \"https://api.example.com/u\"}\n";
    assert!(compile(&base(wrong_id, "")).unwrap_err().to_string().contains("must have id `users`"));
    // Memberships are always full.
    let delta_groups = format!("{ok_users}  - id: groups\n    identity: {{role: memberships, mode: delta}}\n    request: {{url: \"https://api.example.com/g\"}}\n");
    assert!(compile(&base(&delta_groups, "")).unwrap_err().to_string().contains("always full"));
    // full_every_secs is bounded.
    assert!(compile(&base(ok_users, "identity: {full_every_secs: 10}\n")).unwrap_err().to_string().contains("full_every_secs"));
    // Identity blocks outside `kind: identity` are refused.
    let collector = "version: 1\nname: t\nkind: collector\nallow: [{host: api.example.com}]\nstreams:\n  - id: users\n    identity: {role: users}\n    request: {url: \"https://api.example.com/u\"}\n";
    assert!(compile(collector).unwrap_err().to_string().contains("only valid under `kind: identity`"));
    // The bundled specs compile.
    for y in [OKTA_SPEC, ENTRA_SPEC] {
        compile(y).unwrap();
    }
}

#[test]
fn identity_runs_get_higher_but_bounded_limits() {
    let ceilings = engine::default_ceilings();
    let c = engine::compile(&ConnectorSpec::from_yaml(OKTA_SPEC).unwrap(), &ceilings).unwrap();
    let id = engine::identity_ceilings(&ceilings);
    assert!(c.limits.max_pages <= id.max_pages && c.limits.max_pages >= 5000);
    assert!(c.limits.max_run_secs <= ceilings.max_run_secs);
    assert_eq!(id.max_pages, ceilings.max_pages * 10);
}

#[test]
fn rows_and_statuses_are_normalized() {
    for (i, o) in [("ACTIVE", "active"), ("deprovisioned", "disabled"), ("LOCKED_OUT", "suspended"), ("staged", "unknown"), ("x", "unknown")] {
        assert_eq!(account_status(i), o, "{i}");
    }
    assert_eq!(clean_text(" a\u{0}b\nc "), "abc");
    assert_eq!(clean_text(&"é".repeat(3000)).len(), 4096);
    let n = normalize_user(&json!({
        "external_id": "u1", "upn": "a@b.c", "unknown_field": "dropped", "account_status": "LOCKED",
        "manager_external_id": "m1", "last_sign_in_at": "2026-01-01T00:00:00Z", "groups": ["b", "a", "a"],
    }))
    .unwrap();
    assert_eq!(n.row.account_status.as_deref(), Some("suspended"));
    assert_eq!(n.manager_external_id.as_deref(), Some("m1"));
    assert!(n.row.keep_manager);
    assert_eq!(n.reference.as_deref(), Some("a@b.c"));
    assert_eq!(n.row.groups, Some(vec!["a".to_string(), "b".to_string()]));
    assert_eq!(n.row.last_sign_in_at, Some(1_767_225_600_000));
    assert!(!n.row.text.contains_key("unknown_field"));
    assert!(normalize_user(&json!({"upn": "x"})).unwrap_err().contains("external_id"));
    // A row that carries its manager's UPN needs no resolution.
    let n = normalize_user(&json!({"external_id": "u1", "manager_upn": "m@b.c", "manager_external_id": "m1"})).unwrap();
    assert_eq!(n.manager_external_id, None);
}

#[test]
fn shrink_guard_refuses_more_than_half() {
    let g = ShrinkGuard { previous_rows: Some(10), allow: false };
    assert!(g.check("users", 5).is_ok());
    assert!(g.check("users", 4).unwrap_err().starts_with("identity_shrink_refused"));
    assert!(ShrinkGuard { allow: true, ..g }.check("users", 1).is_ok());
    assert!(ShrinkGuard::default().check("users", 1).is_ok(), "no previous full run");
}

// ------------------------------------------------------------ runner

fn identity_feed(yaml: &str) -> FeedDefinition {
    let mut vendor = HashMap::new();
    vendor.insert("API_TOKEN".to_string(), Secret::new(OKTA_TOKEN));
    FeedDefinition {
        feed_id: Uuid::now_v7(),
        name: "Okta directory".into(),
        connector: "okta_users".into(),
        spec_yaml: yaml.into(),
        spec_sha256: spec_sha256(yaml),
        source_type: "identity".into(),
        schedule: None,
        config: config(json!({"OKTA_DOMAIN": "acme.okta.com"})),
        credential_id: Some(Uuid::now_v7()),
        vendor_credentials: vendor,
        max_run_secs: Some(120),
        consecutive_failures: 0,
    }
}

fn runner(mock: &Mock, store: Arc<MemoryFeedStore>, dirs: Option<Arc<MemoryDirectories>>) -> Arc<Runner> {
    let h = harness(mock);
    // Identity feeds never touch the ingest route.
    let ingest = Arc::new(StaticIngest { url: "http://127.0.0.1:9".into(), token: Secret::new("unused-token") });
    let mut cfg = RunnerConfig::new("node-a", h.cfg, ingest);
    cfg.identity = dirs.map(|d| d as Arc<dyn nano_connector::service::directory::IdentityDirectories>);
    Runner::new(store, cfg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_runner_syncs_an_identity_feed_into_its_directory() {
    let st = Arc::new(Mutex::new(OktaState {
        full: vec![u("00u1", "ACTIVE", "CEO", ""), u("00u2", "ACTIVE", "SRE", "")],
        groups: vec![("g1", "Admins", vec!["00u1"])],
        ..Default::default()
    }));
    let mock = start_mock(okta_vendor(st), false).await;
    let store = Arc::new(MemoryFeedStore::default());
    let feed = identity_feed(OKTA_SPEC);
    store.add(feed.clone());
    let dirs = Arc::new(MemoryDirectories::default());
    let r = runner(&mock, store.clone(), Some(dirs.clone()));
    assert_eq!(r.tick().await.unwrap().claimed, 1);
    let recs = r.drain().await;
    assert_eq!(recs[0].status, RunStatus::Success, "{:?}", recs[0].error);
    assert_eq!(recs[0].events, 2, "two user rows written");
    let d = dirs.feed(feed.feed_id);
    let mut live = d.dir.live();
    live.sort();
    assert_eq!(live, ["00u1", "00u2"]);
    assert_eq!(d.dir.get("00u1").unwrap().groups, vec!["Admins".to_string()]);
    assert_eq!(d.outcomes.lock().unwrap().as_slice(), &[(true, None, 2)]);
    let cp = store.checkpoint(feed.feed_id, "users").unwrap();
    assert_eq!(cp["identity_last_full_rows"], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_runner_without_a_directory_fails_identity_feeds_clearly() {
    let mock = start_mock(okta_vendor(Arc::new(Mutex::new(OktaState::default()))), false).await;
    let store = Arc::new(MemoryFeedStore::default());
    let feed = identity_feed(OKTA_SPEC);
    store.add(feed.clone());
    let r = runner(&mock, store.clone(), None);
    r.tick().await.unwrap();
    let recs = r.drain().await;
    assert_eq!(recs[0].status, RunStatus::Failed);
    assert!(recs[0].error.as_deref().unwrap_or_default().starts_with("identity_directory_unconfigured"), "{:?}", recs[0].error);
    assert!(mock.requests().is_empty(), "no vendor call without a directory");
    assert!(store.checkpoint(feed.feed_id, "users").is_none());
}

#[test]
fn bundled_identity_specs_plan_as_feeds_without_a_lane() {
    for slug in ["okta_users", "entra_directory"] {
        let plan = nano_connector::first_party::plan(slug).unwrap();
        assert_eq!(plan.source_type, "identity");
        assert!(nano_connector::service::admin::lanes(&plan, &serde_json::Map::new()).unwrap().is_empty());
        let optional = nano_connector::service::admin::optional_config_keys(&plan.spec_yaml).unwrap();
        assert!(optional.contains("identity_allow_shrink"), "{slug}: {optional:?}");
    }
    let plan = nano_connector::first_party::plan("okta_users").unwrap();
    let mut feed = nano_connector::service::admin::NewFeed {
        name: "Okta directory".into(),
        config: config(json!({"OKTA_DOMAIN": "acme.okta.com", "identity_allow_shrink": "yes"})),
        credential_id: Some(Uuid::now_v7()),
        enabled: true,
        ..Default::default()
    };
    assert!(nano_connector::service::admin::check_inputs(&plan, &feed).unwrap_err().to_string().contains("true or false"));
    feed.config.insert("identity_allow_shrink".into(), json!(true));
    nano_connector::service::admin::check_inputs(&plan, &feed).unwrap();
}


/// NAN-4931 review (P2): a full run is staged until the shrink guard passes.
/// A refused run must leave every row exactly as it was, including users the
/// partial response re-sent with changed attributes or as tombstones.
#[tokio::test]
async fn a_refused_full_run_changes_nothing_it_staged() {
    let dir = Arc::new(MemoryDirectory::default());
    let sink = IdentitySink::new(dir.clone(), 1000);
    let row = |id: &str, title: &str| json!({"external_id": id, "upn": format!("{id}@x.example"), "title": title, "account_status": "active"});
    // Baseline: 4 users.
    sink.users_begin("users", IdentityMode::Full, ShrinkGuard::default()).await.unwrap();
    sink.users_page("users", IdentityMode::Full, &[row("a", "CEO"), row("b", "SRE"), row("c", "Dev"), row("d", "Ops")]).await.unwrap();
    assert_eq!(sink.users_finish("users", IdentityMode::Full).await.unwrap(), Some(4));
    // A permission-scoped response: one re-titled user and one tombstone.
    sink.users_begin("users", IdentityMode::Full, ShrinkGuard { previous_rows: Some(10), allow: false }).await.unwrap();
    sink.users_page("users", IdentityMode::Full, &[row("a", "Changed"), json!({"external_id": "b", "deleted": true})]).await.unwrap();
    let err = sink.users_finish("users", IdentityMode::Full).await.unwrap_err();
    assert!(err.contains("identity_shrink_refused"), "{err}");
    assert_eq!(dir.get("a").unwrap().title.as_deref(), Some("CEO"), "a staged change is not written by a refused run");
    assert_eq!(dir.get("b").unwrap().account_status, "active", "a staged tombstone is not written by a refused run");
    let mut live = dir.live();
    live.sort();
    assert_eq!(live, ["a", "b", "c", "d"]);
}

/// A fence that refuses every write, as the runner's does once the feed was
/// paused, reset, deleted or re-pinned mid-run.
struct LostLease;

#[async_trait::async_trait]
impl WriteFence for LostLease {
    async fn run<'a>(&'a self, _op: FencedWrite<'a>) -> Result<(), String> {
        Err("the feed lease was lost".into())
    }
}

/// NAN-4931 review (P1): directory writes are fenced by the run's lease. A
/// feed deleted (users tombstoned) or reset while a full run is in flight is
/// never resurrected by that run, and its delta pages are refused too.
#[tokio::test]
async fn a_run_that_lost_its_lease_never_writes_the_directory() {
    let dir = Arc::new(MemoryDirectory::default());
    let row = |id: &str| json!({"external_id": id, "upn": format!("{id}@x.example"), "account_status": "active"});
    let sink = IdentitySink::new(dir.clone(), 1000);
    sink.users_begin("users", IdentityMode::Full, ShrinkGuard::default()).await.unwrap();
    sink.users_page("users", IdentityMode::Full, &[row("a"), row("b")]).await.unwrap();
    sink.users_finish("users", IdentityMode::Full).await.unwrap();
    // The operator deletes the feed: its users are tombstoned...
    dir.retire_absent(&Default::default()).await.unwrap();
    assert!(dir.live().is_empty());
    // ...while an older run (now fenced off) finishes its full walk.
    let stale = IdentitySink::new(dir.clone(), 1000).with_fence(Arc::new(LostLease));
    stale.users_begin("users", IdentityMode::Full, ShrinkGuard::default()).await.unwrap();
    stale.users_page("users", IdentityMode::Full, &[row("a"), row("b")]).await.unwrap();
    assert!(stale.users_finish("users", IdentityMode::Full).await.unwrap_err().contains("lease"));
    stale.users_begin("users", IdentityMode::Delta, ShrinkGuard::default()).await.unwrap();
    assert!(stale.users_page("users", IdentityMode::Delta, &[row("a")]).await.is_err());
    stale.memberships_page("groups", &[json!({"member": "a", "group": "Admins"})]).await.unwrap();
    assert!(stale.memberships_finish().await.is_err());
    assert!(dir.live().is_empty(), "no user resurrected by a run without the lease");
}

/// The runner's fence is the claim's lease: pausing the feed (as delete and
/// reset do) fences off the claim it issued earlier.
#[tokio::test]
async fn the_store_fence_refuses_a_claim_after_the_feed_was_paused() {
    use nano_connector::service::FeedStore;
    let store = Arc::new(MemoryFeedStore::default());
    let feed = identity_feed(OKTA_SPEC);
    store.add(feed.clone());
    let claims = store.claim_due("node-a", 1, &|_| 600).await.unwrap();
    let claim = claims.into_iter().next().unwrap();
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let r = ran.clone();
    store.fenced(&claim, Box::pin(async move { r.store(true, std::sync::atomic::Ordering::SeqCst); Ok(()) })).await.unwrap();
    assert!(ran.load(std::sync::atomic::Ordering::SeqCst), "the current claim may write");
    store.set_enabled(feed.feed_id, false);
    let ran2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let r2 = ran2.clone();
    let err = store.fenced(&claim, Box::pin(async move { r2.store(true, std::sync::atomic::Ordering::SeqCst); Ok(()) })).await.unwrap_err();
    assert!(err.contains("lease"), "{err}");
    assert!(!ran2.load(std::sync::atomic::Ordering::SeqCst), "a fenced-off claim's write never runs");
}
