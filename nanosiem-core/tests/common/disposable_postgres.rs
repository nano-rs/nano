// Owned PostgreSQL 18 for explicit acceptance on build workers.
// Never connects to the worker's pre-existing PostgreSQL service.
enum DisposablePgBackend {
    Native {
        root: tempfile::TempDir,
        bin: std::path::PathBuf,
    },
    Docker {
        id: String,
        sudo: bool,
    },
}
struct DisposablePostgres {
    backend: DisposablePgBackend,
    port: u16,
    role: String,
    environment: Vec<(String, Option<std::ffi::OsString>)>,
}
fn test_docker(sudo: bool) -> std::process::Command {
    if sudo {
        let mut command = std::process::Command::new("sudo");
        command.args(["-n", "docker"]);
        command
    } else {
        std::process::Command::new("docker")
    }
}
impl DisposablePostgres {
    fn start(role: &str) -> Self {
        use std::process::{Command, Stdio};
        assert!(
            role.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        let mut candidates = vec![std::path::PathBuf::from("/usr/lib/postgresql/18/bin")];
        candidates.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let native = candidates.into_iter().find(|directory| {
            if !directory.join("pg_ctl").is_file() {
                return false;
            }
            Command::new(directory.join("initdb"))
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .is_some_and(|output| {
                    String::from_utf8_lossy(&output.stdout)
                        .split_whitespace()
                        .last()
                        .is_some_and(|version| version.split('.').next() == Some("18"))
                })
        });
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let backend = if let Some(bin) = native {
            let root = tempfile::Builder::new()
                .prefix("nano-owned-pg-")
                .tempdir()
                .unwrap();
            let data = root.path().join("data");
            let socket = root.path().join("socket");
            std::fs::create_dir(&socket).unwrap();
            let status = Command::new(bin.join("initdb"))
                .args([
                    "--no-locale",
                    "--encoding=UTF8",
                    "--auth=trust",
                    "--username",
                    role,
                ])
                .arg("-D")
                .arg(&data)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "initialize owned PostgreSQL 18");
            let options = format!(
                "-F -h 127.0.0.1 -p {port} -k {} -c max_connections=100",
                socket.display()
            );
            let status = Command::new(bin.join("pg_ctl"))
                .arg("-D")
                .arg(&data)
                .arg("-l")
                .arg(root.path().join("postgres.log"))
                .args(["-w", "-t", "20", "-o", &options, "start"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "start owned PostgreSQL 18");
            DisposablePgBackend::Native { root, bin }
        } else {
            let available = |sudo| {
                test_docker(sudo)
                    .arg("info")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success())
            };
            let sudo = !available(false);
            assert!(
                !sudo || available(true),
                "explicit PostgreSQL acceptance requires PostgreSQL 18 or Docker on the worker"
            );
            // Same image as scripts/validate-activated-upgrade-chain.sh. It is
            // scoped to this worker, binds loopback only and has no shared data.
            let name = format!("nano-test-pg-{}", uuid::Uuid::new_v4().simple());
            let publish = format!("127.0.0.1:{port}:5432");
            let user = format!("POSTGRES_USER={role}");
            let output = test_docker(sudo)
                .args([
                    "run",
                    "--rm",
                    "-d",
                    "--name",
                    &name,
                    "-e",
                    "POSTGRES_HOST_AUTH_METHOD=trust",
                    "-e",
                    &user,
                    "-e",
                    "POSTGRES_DB=postgres",
                    "-p",
                    &publish,
                    "postgres:18",
                ])
                .stderr(Stdio::null())
                .output()
                .expect("launch owned PostgreSQL 18 container");
            assert!(
                output.status.success(),
                "launch owned PostgreSQL 18 container"
            );
            let id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
            assert!(id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
            DisposablePgBackend::Docker { id, sudo }
        };
        let mut cluster = Self {
            backend,
            port,
            role: role.into(),
            environment: Vec::new(),
        };
        if let DisposablePgBackend::Docker { id, sudo } = &cluster.backend {
            let mut ready = false;
            for _ in 0..120 {
                if test_docker(*sudo)
                    .args([
                        "exec",
                        id,
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        role,
                        "-d",
                        "postgres",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success())
                {
                    ready = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            assert!(ready, "owned PostgreSQL 18 did not become ready");
        }
        cluster.set_env("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS", "1");
        cluster
    }
    fn url(&self, database: &str) -> String {
        assert!(
            database
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        format!(
            "postgresql://{}@127.0.0.1:{}/{database}",
            self.role, self.port
        )
    }
    fn set_env(&mut self, name: &str, value: &str) {
        self.environment.push((name.into(), std::env::var_os(name)));
        // Explicit ignored suites run in a dedicated process with one test thread.
        unsafe {
            std::env::set_var(name, value);
        }
    }
}
impl Drop for DisposablePostgres {
    fn drop(&mut self) {
        use std::process::{Command, Stdio};
        match &self.backend {
            DisposablePgBackend::Native { root, bin } => {
                let _ = Command::new(bin.join("pg_ctl"))
                    .arg("-D")
                    .arg(root.path().join("data"))
                    .args(["stop", "-m", "immediate", "-w", "-t", "10"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            DisposablePgBackend::Docker { id, sudo } => {
                let _ = test_docker(*sudo)
                    .args(["rm", "-f", "-v", id])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        for (name, old) in self.environment.drain(..).rev() {
            unsafe {
                match old {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}
