// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

const DSN: &str = "postgresql://nano_runtime:pw@pg.customer.internal:5432/nano?sslmode=verify-full";

fn document() -> Value {
    json!({
        "schema_version": 1,
        "inputs": {
            "domain": "siem.customer.example",
            "idp": {"kind": "oidc", "issuer": "https://idp.customer.example/realms/nano"},
            "connectivity": "connected"
        },
        "derived": {
            "installation_id": "inst-7f3a",
            "organization_id": "org-customer",
            "revision": 3,
            "release_epoch": 2
        },
        "target": {
            "kind": "linux",
            "inputs": {"object_store": "bundled_rustfs", "host_addresses": ["10.0.0.11"]},
            "derived": {"hosts": []}
        }
    })
}

fn deployment(document: &Value) -> Value {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(document).unwrap());
    json!({
        "installationDocument": encoded,
        "postgres": {"runtimeUrl": {"id": "postgres-runtime"}, "migratorUrl": {"id": "postgres-migrator"}, "ca": {"id": "postgres-ca"}},
        "coordination": {"url": {"id": "coordination-url"}, "ca": {"id": "coordination-ca"}},
        "identity": {"sessionSecret": {"id": "session-secret"}, "oidcClient": {"id": "oidc-client"}, "bootstrapApproval": {"id": "bootstrap-approval"}, "recoveryAuthority": {"id": "bootstrap-verifier"}},
        "releaseDigest": format!("sha256:{}", "a".repeat(64)),
        "listen": {"host": "127.0.0.1", "port": 13000}
    })
}

struct Facts {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Facts {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("sovereign");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let facts = Self { _temp: temp, root };
        facts.write(
            DEPLOYMENT_FILE,
            &serde_json::to_vec(&deployment(&document())).unwrap(),
        );
        facts.write(PRODUCT_POSTGRES_RUNTIME_FILE, DSN.as_bytes());
        facts.write(
            PRODUCT_POSTGRES_CA_FILE,
            b"-----BEGIN CERTIFICATE-----\nsynthetic\n",
        );
        facts
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.root.join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn chmod(&self, name: &str, mode: u32) {
        std::fs::set_permissions(self.root.join(name), std::fs::Permissions::from_mode(mode))
            .unwrap();
    }
    fn load(&self) -> Result<SovereignRuntime, SovereignRuntimeError> {
        SovereignRuntime::load(&self.root)
    }
}

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn facts_load_into_typed_runtime_with_fixed_offline_policy() {
    let facts = Facts::new();
    let runtime = facts.load().unwrap();
    assert_eq!(runtime.installation_id(), "inst-7f3a");
    assert_eq!(runtime.organization_id(), "org-customer");
    assert_eq!((runtime.revision(), runtime.release_epoch()), (3, 2));
    assert_eq!(runtime.target(), SovereignTarget::Linux);
    assert_eq!(runtime.connectivity(), SovereignConnectivity::Connected);
    assert_eq!(runtime.browser_origin(), "https://siem.customer.example");
    // Connected or not, the runtime is offline: no egress, private AI only
    // through customer-configured providers, no docs search, license locked.
    assert!(!runtime.egress_jobs_enabled());
    assert!(runtime.private_ai_endpoints_allowed());
    assert!(!runtime.docs_search_enabled());
    assert_eq!(
        runtime.license_mode(),
        SovereignLicenseMode::LockedUnlessValid
    );
}

#[test]
fn database_url_comes_from_facts_with_verify_full_and_the_installation_ca() {
    let facts = Facts::new();
    let runtime = facts.load().unwrap();
    let url = url::Url::parse(runtime.database_url()).unwrap();
    assert_eq!(url.host_str(), Some("pg.customer.internal"));
    assert_eq!(url.username(), "nano_runtime");
    assert_eq!(url.path(), "/nano");
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("sslmode".to_string(), "verify-full".to_string()),
            (
                "sslrootcert".to_string(),
                facts
                    .root
                    .join(PRODUCT_POSTGRES_CA_FILE)
                    .to_str()
                    .unwrap()
                    .to_string()
            ),
        ]
    );
    assert!(!runtime.database_url().contains("localhost"));
    // sqlx accepts the exact URL the pools are built from.
    let options: sqlx::postgres::PgConnectOptions = runtime.database_url().parse().unwrap();
    assert_eq!(options.get_host(), "pg.customer.internal");
}

#[test]
fn air_gapped_connectivity_is_recorded() {
    let facts = Facts::new();
    let mut doc = document();
    doc["inputs"]["connectivity"] = json!("air_gapped");
    facts.write(
        DEPLOYMENT_FILE,
        &serde_json::to_vec(&deployment(&doc)).unwrap(),
    );
    let runtime = facts.load().unwrap();
    assert_eq!(runtime.connectivity(), SovereignConnectivity::AirGapped);
    assert!(!runtime.egress_jobs_enabled());
}

#[test]
fn absent_root_is_not_sovereign_so_hosted_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let detected = detect_at(&temp.path().join("sovereign"), no_env).unwrap();
    assert!(detected.is_none());
    // Hosted env is not inspected when the root is absent.
    let detected = detect_at(&temp.path().join("sovereign"), |name| match name {
        "DATABASE_URL" => Some("postgres://hosted/db".into()),
        "DEPLOYMENT_MODE" => Some("enterprise_shared".into()),
        _ => None,
    })
    .unwrap();
    assert!(detected.is_none());
}

#[cfg(feature = "enterprise")]
#[test]
fn present_root_with_valid_facts_is_sovereign() {
    let facts = Facts::new();
    let runtime = detect_at(&facts.root, no_env).unwrap().expect("sovereign");
    assert_eq!(runtime.installation_id(), "inst-7f3a");
}

#[cfg(not(feature = "enterprise"))]
#[test]
fn open_core_build_refuses_sovereign_facts() {
    let facts = Facts::new();
    assert_eq!(
        detect_at(&facts.root, no_env).err(),
        Some(SovereignRuntimeError::OpenCoreBuild)
    );
}

#[cfg(feature = "enterprise")]
#[test]
fn missing_facts_refuse_boot_without_a_localhost_fallback() {
    for missing in [
        DEPLOYMENT_FILE,
        PRODUCT_POSTGRES_RUNTIME_FILE,
        PRODUCT_POSTGRES_CA_FILE,
    ] {
        let facts = Facts::new();
        std::fs::remove_file(facts.root.join(missing)).unwrap();
        let error = detect_at(&facts.root, no_env).err().expect(missing);
        assert_eq!(
            error,
            SovereignRuntimeError::Unavailable(match missing {
                DEPLOYMENT_FILE => DEPLOYMENT_FILE,
                PRODUCT_POSTGRES_RUNTIME_FILE => PRODUCT_POSTGRES_RUNTIME_FILE,
                _ => PRODUCT_POSTGRES_CA_FILE,
            })
        );
    }
    // An empty mount (materializer never ran) is sovereign and refused.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("sovereign");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(detect_at(&root, no_env).is_err());
}

#[cfg(feature = "enterprise")]
#[test]
fn conflicting_environment_refuses_boot() {
    // Pinned, not derived: dropping a name from the list must fail here.
    assert_eq!(
        CONFLICTING_ENV,
        [
            "DATABASE_URL",
            "LICENSE_URL",
            "HEARTBEAT_URL",
            "LICENSE_TOKEN",
            "HEARTBEAT_TOKEN",
            "CORS_ORIGINS"
        ]
    );
    let facts = Facts::new();
    for name in CONFLICTING_ENV {
        let error = detect_at(&facts.root, |key| (key == name).then(|| "x".to_string()))
            .err()
            .expect(name);
        assert_eq!(error, SovereignRuntimeError::ConflictingEnvironment(name));
    }
    for mode in ["managed", "enterprise_shared", "demo", "bogus"] {
        assert!(matches!(
            detect_at(&facts.root, |key| (key == "DEPLOYMENT_MODE")
                .then(|| mode.to_string())),
            Err(SovereignRuntimeError::ConflictingDeploymentMode(_))
        ));
    }
    for mode in ["", "self-hosted", "selfhosted"] {
        assert!(detect_at(&facts.root, |key| (key == "DEPLOYMENT_MODE")
            .then(|| mode.to_string()))
        .unwrap()
        .is_some());
    }
}

#[test]
fn insecure_material_is_refused() {
    for mode in [0o640, 0o604, 0o660, 0o4600] {
        let facts = Facts::new();
        facts.chmod(PRODUCT_POSTGRES_RUNTIME_FILE, mode);
        assert_eq!(
            facts.load().err(),
            Some(SovereignRuntimeError::InsecureMaterial(
                PRODUCT_POSTGRES_RUNTIME_FILE
            )),
            "{mode:o}"
        );
    }
    // Public root.
    let facts = Facts::new();
    std::fs::set_permissions(&facts.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        facts.load().err(),
        Some(SovereignRuntimeError::InsecureMaterial("installation root"))
    );
    // Symlinked leaf.
    let facts = Facts::new();
    let elsewhere = facts.root.parent().unwrap().join("elsewhere");
    std::fs::write(&elsewhere, DSN).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(facts.root.join(PRODUCT_POSTGRES_RUNTIME_FILE)).unwrap();
    symlink(&elsewhere, facts.root.join(PRODUCT_POSTGRES_RUNTIME_FILE)).unwrap();
    assert_eq!(
        facts.load().err(),
        Some(SovereignRuntimeError::InsecureMaterial(
            PRODUCT_POSTGRES_RUNTIME_FILE
        ))
    );
    // Symlinked root.
    let facts = Facts::new();
    let link = facts.root.parent().unwrap().join("link");
    symlink(&facts.root, &link).unwrap();
    assert_eq!(
        SovereignRuntime::load(&link).err(),
        Some(SovereignRuntimeError::InsecureMaterial("installation root"))
    );
    // Empty and oversized.
    let facts = Facts::new();
    facts.write(PRODUCT_POSTGRES_CA_FILE, b"");
    assert!(facts.load().is_err());
    facts.write(
        PRODUCT_POSTGRES_CA_FILE,
        &vec![b'a'; MAX_MATERIAL_BYTES as usize + 1],
    );
    assert!(facts.load().is_err());
}

#[test]
fn product_transport_must_be_verify_full_only() {
    for dsn in [
        "postgresql://nano@pg.customer.internal/nano",
        "postgresql://nano@pg.customer.internal/nano?sslmode=require",
        "postgresql://nano@pg.customer.internal/nano?sslmode=verify-full&sslmode=disable",
        "postgresql://nano@pg.customer.internal/nano?sslmode=verify-full&sslrootcert=/tmp/ca",
        "postgresql://nano@pg.customer.internal/nano?sslmode=verify-full&options=-crole%3Downer",
        "postgresql://nano@pg.customer.internal/nano?sslmode=verify-full#x",
        "postgresql://pg.customer.internal/nano?sslmode=verify-full",
        "postgresql://nano@pg.customer.internal/?sslmode=verify-full",
        "postgresql://run%0Atime@pg.customer.internal/nano?sslmode=verify-full",
        "mysql://nano@pg.customer.internal/nano?sslmode=verify-full",
        " postgresql://nano@pg.customer.internal/nano?sslmode=verify-full",
        "postgresql://nano@pg.customer.internal/nano?sslmode=verify-full\n",
    ] {
        let facts = Facts::new();
        facts.write(PRODUCT_POSTGRES_RUNTIME_FILE, dsn.as_bytes());
        assert!(
            matches!(
                facts.load(),
                Err(SovereignRuntimeError::InvalidTransport(_))
            ),
            "{dsn:?}"
        );
    }
}

#[test]
fn deployment_binding_must_be_the_exact_c06_shape() {
    let mutations: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|v| v["extra"] = json!(true)),
        Box::new(|v| v["postgres"]["migratorUrl"] = json!({"id": "postgres-runtime"})),
        Box::new(|v| v["postgres"]["ca"] = json!({"id": "../etc/passwd"})),
        Box::new(|v| v["identity"]["bootstrapApproval"] = json!({"id": "bootstrap-verifier"})),
        Box::new(|v| v["releaseDigest"] = json!("sha256:XYZ")),
        Box::new(|v| v["installationDocument"] = json!("not base64!")),
        Box::new(|v| {
            let s = format!("{}\n", v["installationDocument"].as_str().unwrap());
            v["installationDocument"] = json!(s);
        }),
        Box::new(|v| {
            v.as_object_mut().unwrap().remove("listen");
        }),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let facts = Facts::new();
        let mut wire = deployment(&document());
        mutate(&mut wire);
        facts.write(DEPLOYMENT_FILE, &serde_json::to_vec(&wire).unwrap());
        assert!(
            matches!(
                facts.load(),
                Err(SovereignRuntimeError::InvalidDeployment(_))
            ),
            "mutation {index}"
        );
    }
}

#[test]
fn installation_document_must_be_c01_v1() {
    let mutations: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|v| v["schema_version"] = json!(2)),
        Box::new(|v| v["derived"]["installation_id"] = json!("Inst/../x")),
        Box::new(|v| v["derived"]["revision"] = json!(0)),
        Box::new(|v| v["inputs"]["domain"] = json!("127.0.0.1")),
        Box::new(|v| v["inputs"]["idp"]["issuer"] = json!("http://idp.customer.example")),
        Box::new(|v| v["inputs"]["connectivity"] = json!("online")),
        Box::new(|v| v["target"]["kind"] = json!("azure")),
        Box::new(|v| v["unknown"] = json!(1)),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let facts = Facts::new();
        let mut doc = document();
        mutate(&mut doc);
        facts.write(
            DEPLOYMENT_FILE,
            &serde_json::to_vec(&deployment(&doc)).unwrap(),
        );
        assert!(
            matches!(
                facts.load(),
                Err(SovereignRuntimeError::InvalidInstallation(_))
            ),
            "mutation {index}"
        );
    }
}

#[test]
fn errors_never_carry_secret_material() {
    let facts = Facts::new();
    facts.write(
        PRODUCT_POSTGRES_RUNTIME_FILE,
        b"postgresql://nano:hunter2-secret@pg.customer.internal/nano?sslmode=disable",
    );
    let message = facts.load().err().unwrap().to_string();
    assert!(!message.contains("hunter2"), "{message}");
}

/// NAN-4686: the single-host installer's renderer
/// (scripts/sovereign/render_single_host_facts.py, run by
/// scripts/sovereign/single-host.sh) produces facts this reader accepts,
/// with the installer's real DSN shape, modes and ownership.
#[test]
fn single_host_installer_renders_facts_the_runtime_loads() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::write(
        dir.join("installation.json"),
        r#"{"domain":"10-1-2-3.sslip.io","installation_id":"inst-0123456789abcdef","organization_id":"org-fedcba9876543210"}"#,
    )
    .unwrap();
    // Password with URL-reserved bytes: the renderer must percent-encode it.
    std::fs::write(
        dir.join(".env"),
        "POSTGRES_PASSWORD=p@ss/w:rd?#%\nJWT_SECRET=x\n",
    )
    .unwrap();
    std::fs::write(dir.join("ca.crt"), b"-----BEGIN CERTIFICATE-----\nsynthetic\n").unwrap();
    let out = dir.join("app");
    // SAFETY: geteuid/getegid have no preconditions.
    let owner = unsafe { format!("{}:{}", libc::geteuid(), libc::getegid()) };
    let status = std::process::Command::new("python3")
        .arg(repo.join("scripts/sovereign/render_single_host_facts.py"))
        .args(["--out".as_ref(), out.as_os_str()])
        .args(["--installation".as_ref(), dir.join("installation.json").as_os_str()])
        .args(["--env-file".as_ref(), dir.join(".env").as_os_str()])
        .args(["--ca-file".as_ref(), dir.join("ca.crt").as_os_str()])
        .args(["--release-digest", &format!("sha256:{}", "b".repeat(64))])
        .args(["--owner", &owner])
        .status()
        .expect("run python3");
    assert!(status.success());

    assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
    for name in [DEPLOYMENT_FILE, PRODUCT_POSTGRES_RUNTIME_FILE, PRODUCT_POSTGRES_CA_FILE] {
        let mode = std::fs::metadata(out.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400, "{name}");
    }
    let runtime = SovereignRuntime::load(&out).expect("installer-rendered facts load");
    assert_eq!(runtime.target(), SovereignTarget::Linux);
    assert_eq!(runtime.connectivity(), SovereignConnectivity::Connected);
    assert_eq!(runtime.domain(), "10-1-2-3.sslip.io");
    assert_eq!(runtime.browser_origin(), "https://10-1-2-3.sslip.io");
    assert_eq!(runtime.installation_id(), "inst-0123456789abcdef");
    assert_eq!(runtime.organization_id(), "org-fedcba9876543210");
    let url = url::Url::parse(runtime.database_url()).unwrap();
    assert_eq!(url.host_str(), Some("postgres"));
    assert_eq!(url.username(), "nanosiem");
    assert_eq!(url.password(), Some("p%40ss%2Fw%3Ard%3F%23%25"));
    assert_eq!(url.path(), "/nanosiem");
    let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    assert_eq!(query[0], ("sslmode".into(), "verify-full".into()));
    assert_eq!(query[1].0, "sslrootcert");
    assert!(query[1].1.ends_with("/product-postgres-ca"));

    // Re-rendering in place (installer re-run) replaces the files and still loads.
    let status = std::process::Command::new("python3")
        .arg(repo.join("scripts/sovereign/render_single_host_facts.py"))
        .args(["--out".as_ref(), out.as_os_str()])
        .args(["--installation".as_ref(), dir.join("installation.json").as_os_str()])
        .args(["--env-file".as_ref(), dir.join(".env").as_os_str()])
        .args(["--ca-file".as_ref(), dir.join("ca.crt").as_os_str()])
        .args(["--release-digest", &format!("sha256:{}", "c".repeat(64))])
        .args(["--owner", &owner])
        .status()
        .unwrap();
    assert!(status.success());
    SovereignRuntime::load(&out).expect("re-rendered facts load");
}
