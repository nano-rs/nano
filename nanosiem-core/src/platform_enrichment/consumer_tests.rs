// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::platform_enrichment::test_support::{entry, ioc, metadata, ring, seal};
use std::sync::Mutex;

fn feeds(now: DateTime<Utc>) -> BTreeMap<String, portable::FeedEntry> {
    [
        ("ipinfo_lite".to_string(), entry("ipinfo_lite", 7, now, 1)),
        ("threatfox".to_string(), entry("threatfox", 169, now, 1)),
        ("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 167, now, 1)),
    ]
    .into()
}

fn sealed(now: DateTime<Utc>, sequence: u64) -> crate::platform_enrichment::test_support::Sealed {
    seal(
        feeds(now),
        Some(b"MMDB"),
        &[
            ioc("threatfox", "domain", "evil.example", "botnet_cc"),
            ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit"),
        ],
        sequence,
        now,
    )
}

#[test]
fn current_release_metadata_is_verified_before_the_download_is_followed() {
    let now = Utc::now();
    let s = sealed(now, 10);
    let ok = parse_current(&metadata(&s.signed, "https://bundles.example/b.nanfeed?sig=1"), &ring()).unwrap();
    assert_eq!(ok.signed, s.signed);
    assert_eq!(ok.bundle_url, "https://bundles.example/b.nanfeed?sig=1");

    // Untrusted signer (the production ring does not hold the fixture key).
    assert!(matches!(
        parse_current(&metadata(&s.signed, "https://bundles.example/b"), &KeyRing::production()),
        Err(ConsumerError::Refused(_))
    ));
    // Tampered descriptor: the signature no longer covers it.
    let mut tampered = s.signed.clone();
    tampered.descriptor.sequence += 1;
    assert!(matches!(parse_current(&metadata(&tampered, "https://bundles.example/b"), &ring()), Err(ConsumerError::Refused(_))));
    // The advertised digest must be the signed one.
    let mut body: serde_json::Value = serde_json::from_slice(&metadata(&s.signed, "https://bundles.example/b")).unwrap();
    body["bundle_sha256"] = serde_json::json!("0".repeat(64));
    assert!(matches!(parse_current(&serde_json::to_vec(&body).unwrap(), &ring()), Err(ConsumerError::Refused(_))));
    // Only plain https download capabilities are followed.
    for url in ["http://bundles.example/b", "https://user:pw@bundles.example/b", "https://bundles.example/a b"] {
        assert!(matches!(parse_current(&metadata(&s.signed, url), &ring()), Err(ConsumerError::Refused(_))), "{url}");
    }
}

#[test]
fn plan_skips_only_expired_feeds() {
    let now = Utc::now();
    let mut d = sealed(now, 1).signed.descriptor;
    let (load, skip) = plan_feeds(&d, now);
    assert_eq!(load.keys().collect::<Vec<_>>(), ["ipinfo_lite", "threatfox", "tor_exit_nodes"]);
    assert!(skip.is_empty());

    d.feeds.get_mut("threatfox").unwrap().hard_expiry = now - chrono::Duration::seconds(1);
    let (load, skip) = plan_feeds(&d, now);
    assert!(!load.contains_key("threatfox"));
    assert!(skip["threatfox"].contains("hard expiry"));
    // NAN-4959: IPinfo is always wanted from the bundle (no BYO token skip).
    assert!(load.contains_key("ipinfo_lite"));
}

#[test]
fn current_means_same_descriptor_and_every_wanted_feed_active() {
    let now = Utc::now();
    let d = sealed(now, 5).signed.descriptor;
    let active = |ids: &[&str]| -> BTreeMap<String, FeedInstall> {
        ids.iter().map(|id| (id.to_string(), FeedInstall { loaded: 1, active: true, detail: None })).collect()
    };
    let all = active(&["ipinfo_lite", "threatfox", "tor_exit_nodes"]);
    assert!(is_current(Some(&d), &all, &d, now));
    assert!(!is_current(None, &all, &d, now));
    let mut newer = d.clone();
    newer.sequence += 1;
    assert!(!is_current(Some(&d), &all, &newer, now));
    // NAN-4959 upgrade: an install from before this change withdrew IPinfo for
    // a BYO token. The same descriptor is no longer current, so the next check
    // reinstalls it and IPinfo stamps from the bundle again.
    let without_ip = active(&["threatfox", "tor_exit_nodes"]);
    assert!(!is_current(Some(&d), &without_ip, &d, now));
}

#[test]
fn installed_descriptor_is_revalidated_without_its_signature() {
    let now = Utc::now();
    let s = sealed(now, 3);
    let stored = serde_json::to_value(&s.signed).unwrap();
    assert_eq!(installed_descriptor(Some(&stored)), Some(s.signed.descriptor.clone()));
    let mut broken = stored.clone();
    broken["descriptor"]["notice"] = serde_json::json!("not the notice");
    assert_eq!(installed_descriptor(Some(&broken)), None);
    assert_eq!(installed_descriptor(None), None);
}

#[test]
fn staging_copies_regular_files_and_refuses_symlinks() {
    let now = Utc::now();
    let s = sealed(now, 3);
    let dest = s.dir.path().join("staged");
    let sha = stage_copy(&s.path, &dest).unwrap();
    assert_eq!(sha, hex::encode(Sha256::digest(std::fs::read(&s.path).unwrap())));
    let link = s.dir.path().join("link");
    std::os::unix::fs::symlink(&s.path, &link).unwrap();
    assert!(matches!(stage_copy(&link, &s.dir.path().join("x")), Err(ConsumerError::Refused(_))));
}

#[test]
fn outcome_serializes_with_a_tag() {
    let v = serde_json::to_value(Outcome::Current { sequence: 4 }).unwrap();
    assert_eq!(v, serde_json::json!({"outcome": "current", "sequence": 4}));
}

struct FakeHttp {
    responses: Mutex<Vec<(String, MetadataResponse)>>,
    seen: Mutex<Vec<(String, bool)>>,
}

#[async_trait]
impl FeedHttp for FakeHttp {
    async fn metadata(&self, url: &str, license: Option<&[u8]>) -> Result<MetadataResponse, String> {
        self.seen.lock().unwrap().push((url.to_string(), license.is_some()));
        let responses = self.responses.lock().unwrap();
        let (_, r) = responses.iter().find(|(u, _)| u == url).ok_or_else(|| "unexpected url".to_string())?;
        // Status 0 stands for a transport (connect) error.
        if r.status == 0 {
            return Err("error sending request: connection refused".into());
        }
        Ok(r.clone())
    }
    async fn download(&self, _url: &str, _dest: &Path, _cap: u64) -> Result<String, String> {
        Err("not used".into())
    }
}

fn consumer(config: ConsumerConfig, http: Arc<FakeHttp>) -> PlatformFeedConsumer {
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://nobody@127.0.0.1:1/none").unwrap();
    let ch = clickhouse::Client::default();
    PlatformFeedConsumer::new(StateRepository::new(pool), ClickHouseLoader::new(ch.clone(), ch), config)
        .with_ring(ring())
        .with_http(http)
}

fn config(license: Option<Vec<u8>>, mirror: Option<&str>) -> ConsumerConfig {
    ConsumerConfig {
        open_url: "https://feeds.example/open".into(),
        sovereign_url: "https://feeds.example/sovereign".into(),
        mirror_url: mirror.map(str::to_string),
        license,
        work_dir: std::env::temp_dir(),
        poll_interval: Duration::from_secs(3600),
        auto_update: true,
    }
}

#[tokio::test]
async fn a_refused_license_falls_back_to_the_open_route() {
    let now = Utc::now();
    let s = sealed(now, 9);
    let http = Arc::new(FakeHttp {
        responses: Mutex::new(vec![
            ("https://feeds.example/sovereign".into(), MetadataResponse { status: 401, body: br#"{"code":"license_unknown_issuer"}"#.to_vec() }),
            ("https://feeds.example/open".into(), MetadataResponse { status: 200, body: metadata(&s.signed, "https://b.example/x") }),
        ]),
        seen: Mutex::new(Vec::new()),
    });
    let c = consumer(config(Some(b"H01-license".to_vec()), None), http.clone());
    let (release, channel) = c.fetch_release().await.unwrap();
    assert_eq!(channel, Channel::Open);
    assert_eq!(release.signed, s.signed);
    assert_eq!(
        *http.seen.lock().unwrap(),
        vec![("https://feeds.example/sovereign".to_string(), true), ("https://feeds.example/open".to_string(), false)]
    );
}

#[tokio::test]
async fn an_accepted_license_uses_the_sovereign_route_and_a_mirror_wins() {
    let now = Utc::now();
    let s = sealed(now, 9);
    let ok = MetadataResponse { status: 200, body: metadata(&s.signed, "https://b.example/x") };
    let http = Arc::new(FakeHttp {
        responses: Mutex::new(vec![
            ("https://feeds.example/sovereign".into(), ok.clone()),
            ("https://mirror.example/current".into(), ok),
        ]),
        seen: Mutex::new(Vec::new()),
    });
    let c = consumer(config(Some(b"H01-license".to_vec()), None), http.clone());
    assert_eq!(c.fetch_release().await.unwrap().1, Channel::Sovereign);
    let m = consumer(config(None, Some("https://mirror.example/current")), http.clone());
    assert_eq!(m.fetch_release().await.unwrap().1, Channel::Mirror);
}

#[tokio::test]
async fn the_online_check_is_disabled_in_air_gap_mode() {
    let http = Arc::new(FakeHttp { responses: Mutex::new(Vec::new()), seen: Mutex::new(Vec::new()) });
    let mut cfg = config(None, None);
    cfg.auto_update = false;
    let c = consumer(cfg, http.clone());
    assert!(matches!(c.check_online().await, Err(ConsumerError::Disabled)));
    assert!(http.seen.lock().unwrap().is_empty());
}

/// NAN-4948 review P1: the work dir must be service-owned with no group/other
/// access; an existing dir that is not is refused, never chmod-repaired.
#[test]
fn work_dir_is_created_private_and_a_loose_existing_one_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("a/platform-feeds");
    let made = ensure_private_dir(&dir).unwrap();
    assert_eq!(std::fs::metadata(&made).unwrap().permissions().mode() & 0o777, 0o700);
    ensure_private_dir(&dir).unwrap();

    let loose = root.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = ensure_private_dir(&loose).unwrap_err().to_string();
    assert!(err.contains("0700"), "{err}");
    assert_eq!(std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777, 0o777, "not repaired");

    let link = root.path().join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    assert!(ensure_private_dir(&link).is_err());
    let file = root.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(ensure_private_dir(&file).is_err());
}

/// NAN-4948 review P2: a feed re-introduced after being omitted cannot go
/// below the highest revision ever committed for it.
#[test]
fn high_water_fence_survives_a_feed_being_omitted() {
    let now = Utc::now();
    let d = sealed(now, 12).signed.descriptor; // threatfox revision 169
    let hw: BTreeMap<String, i64> = [("threatfox".to_string(), 170)].into();
    let err = check_high_water(&d, &hw).unwrap_err().to_string();
    assert!(err.contains("threatfox revision 169 is older than revision 170"), "{err}");
    let ok: BTreeMap<String, i64> = [("threatfox".to_string(), 169), ("tor_exit_nodes".to_string(), 1)].into();
    check_high_water(&d, &ok).unwrap();
    check_high_water(&d, &BTreeMap::new()).unwrap();
}

#[test]
fn next_check_follows_the_leader_schedule() {
    let now = Utc::now();
    let mut status = build_status(None, &StatusContext { auto_update: true, now });
    let hour = Duration::from_secs(3600);
    assert_eq!(next_check_at(&status, hour), None, "no check yet");
    status.last_check_at = Some(now);
    status.last_check_status = Some("current".into());
    assert_eq!(next_check_at(&status, hour), Some(now + chrono::Duration::hours(1)));
    status.last_check_status = Some("failed".into());
    assert_eq!(next_check_at(&status, hour), Some(now + chrono::Duration::seconds(RETRY_SECS as i64)));
    status.auto_update = false;
    assert_eq!(next_check_at(&status, hour), None, "air-gap: no scheduled check");
}

/// NAN-5220 review M1: a sovereign outage, budget refusal or connect error
/// never stops feed updates; the open route is used.
#[tokio::test]
async fn a_sovereign_outage_budget_or_connect_error_falls_back_to_the_open_route() {
    let now = Utc::now();
    let s = sealed(now, 9);
    for sovereign in [
        MetadataResponse { status: 503, body: br#"{"code":"license_verification_unavailable"}"#.to_vec() },
        MetadataResponse { status: 429, body: br#"{"code":"feed_budget_exhausted"}"#.to_vec() },
        MetadataResponse { status: 0, body: Vec::new() },
    ] {
        let label = sovereign.status;
        let http = Arc::new(FakeHttp {
            responses: Mutex::new(vec![
                ("https://feeds.example/sovereign".into(), sovereign),
                ("https://feeds.example/open".into(), MetadataResponse { status: 200, body: metadata(&s.signed, "https://b.example/x") }),
            ]),
            seen: Mutex::new(Vec::new()),
        });
        let c = consumer(config(Some(b"H01-license".to_vec()), None), http.clone());
        let (release, channel) = c.fetch_release().await.unwrap_or_else(|e| panic!("sovereign {label}: {e}"));
        assert_eq!(channel, Channel::Open, "sovereign {label}");
        assert_eq!(release.signed, s.signed);
        assert_eq!(
            *http.seen.lock().unwrap(),
            vec![("https://feeds.example/sovereign".to_string(), true), ("https://feeds.example/open".to_string(), false)],
            "sovereign {label}"
        );
    }
}

/// The open route itself failing is still an error (nothing to fall back to).
#[tokio::test]
async fn an_open_route_failure_after_a_sovereign_failure_is_reported() {
    let http = Arc::new(FakeHttp {
        responses: Mutex::new(vec![
            ("https://feeds.example/sovereign".into(), MetadataResponse { status: 503, body: Vec::new() }),
            ("https://feeds.example/open".into(), MetadataResponse { status: 0, body: Vec::new() }),
        ]),
        seen: Mutex::new(Vec::new()),
    });
    let c = consumer(config(Some(b"H01-license".to_vec()), None), http);
    assert!(matches!(c.fetch_release().await, Err(ConsumerError::Fetch(_))));
}
