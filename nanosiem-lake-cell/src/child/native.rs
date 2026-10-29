// SPDX-License-Identifier: AGPL-3.0-or-later
//! Credential-free receiver preparation. No parent writer/readiness authority.
use super::*;
use crate::contract::{NativeChildService, NativeLandingAssignment};
use std::io;
use std::os::fd::AsRawFd;

pub enum ServiceBoot {
    Hosted(Bootstrapped),
    Native(NativeBootstrapped),
}
/// Constructed only after the actual single-threaded jail and NativeRun frame.
/// It deliberately has no secret field or conversion to the hosted bootstrap.
pub struct NativeBootstrapped {
    assignment: NativeLandingAssignment,
    control: OwnedFd,
    part_channel: Option<OwnedFd>,
}
impl NativeBootstrapped {
    pub fn assignment(&self) -> &NativeLandingAssignment {
        &self.assignment
    }
    /// H02 B2: the one verified part channel of a parts service (taken once;
    /// requires a Tokio runtime). `None` for LandingBytesV1.
    pub fn take_part_channel(&mut self) -> io::Result<Option<crate::part_channel::PartChannel>> {
        let (Some(fd), Some(limits)) = (self.part_channel.take(), self.assignment.part_channel) else {
            return Ok(None);
        };
        crate::part_channel::PartChannel::new(fd, limits).map(Some)
    }
    pub fn into_async(self) -> io::Result<(NativeLandingAssignment, NativeControlChannel)> {
        // A parts service holds exactly one fd (its part channel): no Rpc.
        let rpc_allowed = self.assignment.part_channel.is_none();
        Ok((
            self.assignment,
            NativeControlChannel {
                sock: Arc::new(AsyncSeqpacket::new(self.control)?),
                rpc_allowed,
            },
        ))
    }
}
/// Leaf transport only, not a Root witness. No credential request/exchange,
/// finding append or ingest-connect API is available on this type.
#[derive(Clone)]
pub struct NativeControlChannel {
    sock: Arc<AsyncSeqpacket>,
    /// Only LandingBytesV1 accepts per-request streams (H02 CP35 P2-1).
    rpc_allowed: bool,
}
/// Closed, value-free native liveness: counters and a flag, no strings,
/// maps or JSON. Projected into the shared frame with every other field
/// at its default, so no hosted diagnostic can be expressed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeHeartbeat {
    pub busy: bool,
    pub queue_depth: u64,
    pub last_progress_unix_ms: u64,
}
impl NativeHeartbeat {
    fn frame(self) -> Heartbeat {
        Heartbeat {
            busy: self.busy,
            queue_depth: self.queue_depth,
            last_progress_unix_ms: self.last_progress_unix_ms,
            ..Heartbeat::default()
        }
    }
}
pub enum NativeEvent {
    Rpc {
        request_id: u64,
        stream: tokio::net::UnixStream,
    },
    Shutdown {
        grace: Duration,
    },
    Closed,
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "native byte service protocol denied",
    )
}
impl NativeControlChannel {
    pub async fn next_event(&self) -> io::Result<NativeEvent> {
        let Some((message, fds)) = self.sock.recv_json::<ToChild>().await? else {
            return Ok(NativeEvent::Closed);
        };
        decode_event(message, fds, self.rpc_allowed)
    }
    /// Value-free liveness only. The hosted `Heartbeat` carries free-form
    /// JSON/string diagnostics; the native leaf can never forward them.
    pub async fn heartbeat(&self, heartbeat: NativeHeartbeat) -> io::Result<()> {
        self.sock
            .send_json(&ToSupervisor::Heartbeat(heartbeat.frame()), &[])
            .await
    }
    pub async fn fatal(&self) -> io::Result<()> {
        // Fixed value-free refusal; no input/secret/native path enters logs.
        self.sock
            .send_json(
                &ToSupervisor::Fatal {
                    error: "native byte service refused".into(),
                },
                &[],
            )
            .await
    }
}
fn decode_event(message: ToChild, mut fds: Vec<OwnedFd>, rpc_allowed: bool) -> io::Result<NativeEvent> {
    match message {
        ToChild::Rpc { request_id } if rpc_allowed && fds.len() == 1 => {
            let fd = fds.remove(0);
            let mut kind: libc::c_int = 0;
            let mut domain: libc::c_int = 0;
            let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
            // SAFETY: live owned fd and correctly sized writable option output.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut libc::c_int).cast(),
                    &mut size,
                )
            } != 0
                || kind != libc::SOCK_STREAM
            {
                return Err(refused());
            }
            size = std::mem::size_of_val(&domain) as libc::socklen_t;
            // SAFETY: same owned fd and live output for Linux SO_DOMAIN.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_DOMAIN,
                    (&mut domain as *mut libc::c_int).cast(),
                    &mut size,
                )
            } != 0
                || domain != libc::AF_UNIX
            {
                return Err(refused());
            }
            let stream = std::os::unix::net::UnixStream::from(fd);
            stream.peer_addr()?;
            stream.set_nonblocking(true)?;
            Ok(NativeEvent::Rpc {
                request_id,
                stream: tokio::net::UnixStream::from_std(stream)?,
            })
        }
        ToChild::Shutdown { grace_ms } if fds.is_empty() => Ok(NativeEvent::Shutdown {
            grace: Duration::from_millis(grace_ms),
        }),
        // In particular, Secrets/memfd is NEVER read on this transport.
        _ => Err(refused()),
    }
}
/// Shared by the receiver and the parent projection, so both describe the
/// same reduced isolation and never diverge.
pub(crate) fn validate_assignment(
    supported: &[NativeChildService],
    protocol: u32,
    service: NativeChildService,
    assignment: &NativeLandingAssignment,
    fds: &[OwnedFd],
) -> anyhow::Result<()> {
    let cgroup = assignment.jail.cgroup_dir.as_ref();
    // H02 B2: the service fixes the role, its own state dir and its worker
    // closure. Only parts services carry (valid) part-channel limits.
    let role = service.role();
    let state = std::path::Path::new("/cell/data/tenants")
        .join(assignment.tenant.as_str())
        .join(role.as_str());
    let worker_root = match role {
        crate::contract::Role::Query => "/cell/workers/query",
        _ => "/cell/workers/ingest",
    };
    let normal = |path: &std::path::Path| {
        !path.as_os_str().as_encoded_bytes().contains(&0)
            && path.components().all(|part| {
                matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
    };
    anyhow::ensure!(
        crate::contract::valid_native_services(supported)
            && supported.contains(&service)
            && protocol == PROTOCOL_VERSION
            && fds.is_empty(),
        "native service was not advertised"
    );
    anyhow::ensure!(
        !assignment.cell_id.is_empty()
            && assignment.cell_id.len() <= 63
            && assignment
                .cell_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
            && assignment.memory_cap_bytes > 0
            && assignment.cpu_millis > 0
            && assignment.state_dir == state
            && assignment.tmp_dir == state.join("tmp")
            && normal(&assignment.state_dir)
            && normal(&assignment.tmp_dir)
            && assignment.jail.uid > 0
            && assignment.jail.gid > 0
            && assignment.jail.rw_paths == [state]
            && assignment.jail.require_landlock
            && assignment.jail.ro_paths.is_empty()
            && assignment.jail.tcp_connect_ports.is_empty()
            && !assignment.jail.system_ro_paths.is_empty()
            && assignment
                .jail
                .system_ro_paths
                .iter()
                .all(|path| normal(path)
                    && ["/cell/release", worker_root]
                        .iter()
                        .any(|root| path.starts_with(root)))
            && match assignment.part_channel {
                Some(limits) => service.has_part_channel() && limits.valid(),
                None => !service.has_part_channel(),
            }
            && assignment
                .jail
                .max_processes
                .is_some_and(|value| value > 0 && value <= 4096)
            && assignment.jail.max_open_files > 0
            && assignment.jail.max_open_files <= 65536
            && cgroup.is_some_and(|path| !path.as_os_str().is_empty()
                && !path.as_os_str().as_encoded_bytes().contains(&0)
                && !path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))),
        "native byte service isolation is required"
    );
    Ok(())
}
/// `NativeRun` for `service`: no fd for LandingBytesV1; exactly one part
/// channel (a unix stream whose peer is our parent, the supervisor) for the
/// parts services. Anything else refuses before Ready.
fn accept_run(service: NativeChildService, message: ToChild, mut fds: Vec<OwnedFd>) -> io::Result<Option<OwnedFd>> {
    match message {
        ToChild::NativeRun { service: received } if received == service => {
            if !service.has_part_channel() {
                return if fds.is_empty() { Ok(None) } else { Err(refused()) };
            }
            if fds.len() != 1 {
                return Err(refused());
            }
            let fd = fds.remove(0);
            // SAFETY: getppid never fails.
            let parent = unsafe { libc::getppid() };
            crate::part_channel::verify_received(&fd, parent).map_err(|_| refused())?;
            Ok(Some(fd))
        }
        // There is intentionally no secret-reader dependency on this path.
        _ => Err(refused()),
    }
}
pub(super) fn bootstrap_native(
    control: OwnedFd,
    supported: &[NativeChildService],
    protocol: u32,
    service: NativeChildService,
    assignment: NativeLandingAssignment,
    fds: Vec<OwnedFd>,
) -> anyhow::Result<ServiceBoot> {
    validate_assignment(supported, protocol, service, &assignment, &fds)?;
    let report = jail::apply_native(&assignment.jail).context("native service jail refused")?;
    anyhow::ensure!(
        report.seccomp && report.cgroupns && report.landlock != "none",
        "native service jail incomplete"
    );
    std::env::set_var("TMPDIR", &assignment.tmp_dir);
    std::env::set_var("HOME", &assignment.state_dir);
    std::env::set_current_dir(&assignment.state_dir).context("native service state directory")?;
    send(
        &control,
        &ToSupervisor::Jailed {
            uid: report.uid,
            gid: report.gid,
            landlock: report.landlock,
            seccomp: report.seccomp,
            cgroupns: report.cgroupns,
        },
    )?;
    let Some((message, fds)) = fdpass::recv_json::<ToChild>(control.as_fd())? else {
        bail!("native service controller closed");
    };
    let part_channel = accept_run(service, message, fds)?;
    send(&control, &ToSupervisor::Ready)?;
    Ok(ServiceBoot::Native(NativeBootstrapped {
        assignment,
        control,
        part_channel,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{JailSpec, TenantId};
    use std::path::PathBuf;

    fn assignment() -> NativeLandingAssignment {
        NativeLandingAssignment {
            tenant: TenantId::new("tenant-a").unwrap(),
            cell_id: "cell-a".into(),
            state_dir: "/cell/data/tenants/tenant-a/landing".into(),
            tmp_dir: "/cell/data/tenants/tenant-a/landing/tmp".into(),
            memory_cap_bytes: 512 * 1024 * 1024,
            cpu_millis: 100,
            jail: JailSpec {
                uid: 20020,
                gid: 20000,
                rw_paths: vec!["/cell/data/tenants/tenant-a/landing".into()],
                ro_paths: vec![],
                system_ro_paths: vec!["/cell/workers/ingest".into()],
                tcp_connect_ports: vec![],
                cgroup_dir: Some("tenant-a/landing".into()),
                require_landlock: true,
                max_processes: Some(64),
                max_open_files: 65536,
            },
            part_channel: None,
        }
    }
    /// H02 B2: the same payload for a parts service of `role`.
    fn parts_assignment(role: crate::contract::Role) -> NativeLandingAssignment {
        let mut a = assignment();
        let state = PathBuf::from("/cell/data/tenants/tenant-a").join(role.as_str());
        a.tmp_dir = state.join("tmp");
        a.jail.rw_paths = vec![state.clone()];
        a.state_dir = state;
        a.jail.cgroup_dir = Some(PathBuf::from("tenant-a").join(role.as_str()));
        a.jail.system_ro_paths = vec![if role == crate::contract::Role::Query { "/cell/workers/query/bin" } else { "/cell/workers/ingest/bin" }.into()];
        a.part_channel = Some(crate::contract::PartChannelLimits::DEFAULT);
        a
    }
    fn validate_as(service: NativeChildService, a: &NativeLandingAssignment) -> anyhow::Result<()> {
        validate_assignment(&[service], PROTOCOL_VERSION, service, a, &[])
    }
    #[test]
    fn parts_services_take_their_own_role_dir_closure_and_part_channel() {
        use crate::contract::Role;
        use NativeChildService::*;
        for (service, role) in [(IngestPartsV1, Role::Ingest), (QueryPartsV1, Role::Query)] {
            let good = parts_assignment(role);
            validate_as(service, &good).unwrap();
            // Every other service refuses this payload.
            for other in [LandingBytesV1, IngestPartsV1, QueryPartsV1].into_iter().filter(|s| *s != service) {
                assert!(validate_as(other, &good).is_err(), "{other:?} refuses a {role:?} payload");
            }
            let mut a = good.clone();
            a.part_channel = None;
            assert!(validate_as(service, &a).is_err(), "part channel required");
            let mut a = good.clone();
            a.part_channel = Some(crate::contract::PartChannelLimits { max_frame_bytes: u32::MAX });
            assert!(validate_as(service, &a).is_err(), "bounded frames");
            let mut a = good.clone();
            a.jail.ro_paths = vec!["/cell/data/tenants/tenant-a/parts".into()];
            assert!(validate_as(service, &a).is_err(), "no tenant read path: bytes come through the channel");
            let mut a = good.clone();
            a.jail.tcp_connect_ports = vec![9000];
            assert!(validate_as(service, &a).is_err(), "socketless");
            let mut a = good.clone();
            a.jail.rw_paths = vec!["/cell/data/tenants/tenant-a".into()];
            assert!(validate_as(service, &a).is_err(), "own role dir only");
        }
        // Query never runs from the ingest closure, nor ingest from query's.
        let mut q = parts_assignment(Role::Query);
        q.jail.system_ro_paths = vec!["/cell/workers/ingest/bin".into()];
        assert!(validate_as(QueryPartsV1, &q).is_err());
        let mut i = parts_assignment(Role::Ingest);
        i.jail.system_ro_paths = vec!["/cell/workers/query/bin".into()];
        assert!(validate_as(IngestPartsV1, &i).is_err());
        // Landing never carries a part channel.
        let mut l = assignment();
        l.part_channel = Some(crate::contract::PartChannelLimits::DEFAULT);
        assert!(validate(&l).is_err());
    }
    #[test]
    fn parts_native_run_requires_exactly_one_parent_unix_stream() {
        use NativeChildService::*;
        let run = |service| ToChild::NativeRun { service };
        for service in [IngestPartsV1, QueryPartsV1] {
            assert!(accept_run(service, run(service), vec![]).is_err(), "no channel");
            let memfd = fdpass::secret_memfd(b"synthetic-never-native").unwrap();
            assert!(accept_run(service, run(service), vec![memfd]).is_err(), "memfd is not a channel");
            let (_a, packet) = fdpass::seqpacket_pair().unwrap();
            assert!(accept_run(service, run(service), vec![packet]).is_err(), "seqpacket");
            // A socketpair made by this process: its peer is us, not our parent.
            let (_a, stream) = fdpass::stream_pair().unwrap();
            assert!(accept_run(service, run(service), vec![stream]).is_err(), "peer is not the supervisor");
            let (_a, one) = fdpass::stream_pair().unwrap();
            let (_b, two) = fdpass::stream_pair().unwrap();
            assert!(accept_run(service, run(service), vec![one, two]).is_err(), "exactly one");
            assert!(accept_run(service, run(LandingBytesV1), vec![]).is_err(), "service must match");
        }
    }
    fn validate(a: &NativeLandingAssignment) -> anyhow::Result<()> {
        validate_assignment(
            &[NativeChildService::LandingBytesV1],
            PROTOCOL_VERSION,
            NativeChildService::LandingBytesV1,
            a,
            &[],
        )
    }
    #[test]
    fn reduced_native_frame_carries_no_legacy_credential_fields() {
        let a = assignment();
        validate(&a).unwrap();
        let value = serde_json::to_value(&a).unwrap();
        for field in [
            "control_url",
            "part_signing",
            "outbound_proxy",
            "writer_lease",
            "feed_dir",
            "role",
        ] {
            let mut foreign = value.clone();
            foreign[field] = serde_json::json!("untrusted");
            assert!(
                serde_json::from_value::<NativeLandingAssignment>(foreign).is_err(),
                "closed payload rejects {field}"
            );
        }
    }
    #[test]
    fn advertisement_is_compatible_but_never_selects_an_unadvertised_service() {
        let legacy: ToSupervisor =
            serde_json::from_str(r#"{"type":"hello","pid":1,"protocol_version":2}"#).unwrap();
        let ToSupervisor::Hello {
            native_services, ..
        } = legacy
        else {
            panic!("legacy hello")
        };
        assert!(native_services.is_empty());
        let encoded = serde_json::to_value(ToSupervisor::Hello {
            pid: 1,
            protocol_version: 2,
            native_services: vec![],
        })
        .unwrap();
        assert!(encoded.get("native_services").is_none());
        assert!(crate::contract::valid_native_services(&[]));
        assert!(!crate::contract::valid_native_services(
            &[NativeChildService::LandingBytesV1; 2]
        ));
        assert!(validate_assignment(
            &[],
            2,
            NativeChildService::LandingBytesV1,
            &assignment(),
            &[]
        )
        .is_err());
        assert!(validate_assignment(
            &[NativeChildService::LandingBytesV1],
            1,
            NativeChildService::LandingBytesV1,
            &assignment(),
            &[]
        )
        .is_err());
        assert!(validate_assignment(
            &[NativeChildService::LandingBytesV1; 2],
            2,
            NativeChildService::LandingBytesV1,
            &assignment(),
            &[]
        )
        .is_err());
        assert!(
            serde_json::from_str::<ToChild>(r#"{"type":"native_run","service":"unknown"}"#)
                .is_err()
        );
    }
    #[test]
    fn native_startup_refuses_all_reduced_isolation_descriptions() {
        for fault in [
            "tenant",
            "cell",
            "memory",
            "cpu",
            "state",
            "tmp",
            "uid",
            "gid",
            "landlock",
            "rw",
            "ro",
            "system",
            "network",
            "pids",
            "fds",
            "cgroup",
            "cgroup_escape",
            "cgroup_nul",
        ] {
            let mut a = assignment();
            match fault {
                "tenant" => a.tenant = TenantId::new("tenant-b").unwrap(),
                "cell" => a.cell_id = "cell/foreign".into(),
                "memory" => a.memory_cap_bytes = 0,
                "cpu" => a.cpu_millis = 0,
                "state" => a.state_dir = "/cell/data/tenants/foreign/landing".into(),
                "tmp" => a.tmp_dir = "/tmp".into(),
                "uid" => a.jail.uid = 0,
                "gid" => a.jail.gid = 0,
                "landlock" => a.jail.require_landlock = false,
                "rw" => a.jail.rw_paths.push(PathBuf::from("/")),
                "ro" => a.jail.ro_paths.push(PathBuf::from("/cell/private")),
                "system" => a.jail.system_ro_paths.push(PathBuf::from("/usr/lib")),
                "network" => a.jail.tcp_connect_ports.push(443),
                "pids" => a.jail.max_processes = None,
                "fds" => a.jail.max_open_files = u64::MAX,
                "cgroup" => a.jail.cgroup_dir = None,
                "cgroup_escape" => a.jail.cgroup_dir = Some("../foreign".into()),
                "cgroup_nul" => a.jail.cgroup_dir = Some("tenant-a/land\0ing".into()),
                _ => unreachable!(),
            }
            assert!(
                validate(&a).is_err(),
                "native {fault} must fail before kernel bootstrap"
            );
        }
    }
    #[test]
    fn production_native_bootstrap_denies_before_any_jail_or_ready_frame() {
        for fault in ["unadvertised", "protocol", "foreign_tenant", "secret_fd"] {
            let (parent, child) = fdpass::seqpacket_pair().unwrap();
            let mut a = assignment();
            let mut services = vec![NativeChildService::LandingBytesV1];
            let mut protocol = PROTOCOL_VERSION;
            let mut fds = vec![];
            match fault {
                "unadvertised" => services.clear(),
                "protocol" => protocol = 1,
                "foreign_tenant" => a.tenant = TenantId::new("tenant-b").unwrap(),
                "secret_fd" => fds.push(fdpass::secret_memfd(b"synthetic").unwrap()),
                _ => unreachable!(),
            }
            let error = bootstrap_native(
                child,
                &services,
                protocol,
                NativeChildService::LandingBytesV1,
                a,
                fds,
            )
            .err()
            .expect("must refuse");
            assert!(
                !error.to_string().contains("jail refused"),
                "{fault}: denial precedes jail"
            );
            assert!(
                fdpass::recv_json::<ToSupervisor>(parent.as_fd())
                    .unwrap()
                    .is_none(),
                "{fault}: no Jailed or Ready frame"
            );
        }
    }
    #[tokio::test]
    async fn production_native_channel_denies_secret_fd_without_consuming_its_contents() {
        let (parent, child) = fdpass::seqpacket_pair().unwrap();
        let channel = NativeControlChannel {
            sock: Arc::new(AsyncSeqpacket::new(child).unwrap()),
            rpc_allowed: true,
        };
        // An unsealed, empty pipe is deliberately NOT a readable secret memfd.
        // Refusal must follow the native tag guard without a secret read.
        let (read_end, _write_end) = std::io::pipe().unwrap();
        fdpass::send_json(parent.as_fd(), &ToChild::Secrets, &[read_end.as_fd()]).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), channel.next_event())
            .await
            .expect("native refusal must not block on pipe contents")
            .err()
            .expect("must refuse");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    #[tokio::test]
    async fn native_heartbeat_frame_is_value_free_on_the_actual_channel() {
        let (parent, child) = fdpass::seqpacket_pair().unwrap();
        let channel = NativeControlChannel {
            sock: Arc::new(AsyncSeqpacket::new(child).unwrap()),
            rpc_allowed: true,
        };
        channel
            .heartbeat(NativeHeartbeat {
                busy: true,
                queue_depth: 3,
                last_progress_unix_ms: 9,
            })
            .await
            .unwrap();
        let (frame, fds) = fdpass::recv_json::<serde_json::Value>(parent.as_fd())
            .unwrap()
            .expect("heartbeat frame");
        assert!(fds.is_empty());
        let body = frame.as_object().expect("tagged frame");
        let allowed = [
            "type",
            "busy",
            "queue_depth",
            "last_progress_unix_ms",
            // Numeric/bool defaults the shared frame always serializes.
            "credential_refresh_at_risk",
            "lag_seconds",
            "oldest_unmerged_l0_age_seconds",
            "l0_merge_overdue_seconds",
            "prevalence_behind_seconds",
            "prevalence_behind_entries",
            "prevalence_degraded_seconds",
            "prevalence_degraded_seconds_total",
            "objects_rejected",
            "rows_rejected",
            "retrying",
            "part_gc_deleted_total",
            "rows_committed_total",
        ];
        for (key, value) in body {
            assert!(
                allowed.contains(&key.as_str()),
                "unexpected native field {key}"
            );
            assert!(
                !value.is_string() || key == "type",
                "{key} must not carry a string"
            );
            assert!(
                !value.is_object() && !value.is_array(),
                "{key} must be scalar"
            );
        }
        for hosted in [
            "agent_catalog_custody",
            "ingest_diagnostics",
            "selection_evidence_cache",
            "detail",
            "landing",
            "identity_directory",
            "part_gc_blocked",
            "part_gc_capacity",
        ] {
            assert!(body.get(hosted).is_none(), "{hosted} never native");
        }
        let decoded: ToSupervisor = serde_json::from_value(frame).unwrap();
        let ToSupervisor::Heartbeat(heartbeat) = decoded else {
            panic!("heartbeat")
        };
        assert!(heartbeat.busy && heartbeat.queue_depth == 3);
        assert_eq!(heartbeat.last_progress_unix_ms, 9);
    }
    #[test]
    fn native_assignment_and_run_reject_every_credential_or_extra_fd() {
        let a = assignment();
        let fd = fdpass::secret_memfd(b"synthetic-never-native").unwrap();
        assert!(validate_assignment(
            &[NativeChildService::LandingBytesV1],
            2,
            NativeChildService::LandingBytesV1,
            &a,
            &[fd]
        )
        .is_err());
        assert!(accept_run(
            NativeChildService::LandingBytesV1,
            ToChild::NativeRun {
                service: NativeChildService::LandingBytesV1
            },
            vec![]
        )
        .is_ok());
        for message in [
            ToChild::Secrets,
            ToChild::NativeRun {
                service: NativeChildService::LandingBytesV1,
            },
            ToChild::Rpc { request_id: 1 },
        ] {
            let fd = fdpass::secret_memfd(b"synthetic-never-native").unwrap();
            assert_eq!(
                accept_run(NativeChildService::LandingBytesV1, message, vec![fd])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    #[tokio::test]
    async fn native_transport_accepts_only_a_connected_unix_stream_and_shutdown() {
        use std::io::Write;
        use tokio::io::AsyncReadExt;
        let (mut peer, stream) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = decode_event(ToChild::Rpc { request_id: 7 }, vec![stream.into()], true).unwrap();
        let NativeEvent::Rpc {
            request_id,
            mut stream,
        } = event
        else {
            panic!("fixed RPC")
        };
        assert_eq!(request_id, 7);
        peer.write_all(b"data").unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"data");
        assert!(matches!(
            decode_event(ToChild::Shutdown { grace_ms: 50 }, vec![], true).unwrap(),
            NativeEvent::Shutdown { .. }
        ));
    }
    #[tokio::test]
    async fn native_transport_denies_memfds_network_and_hosted_messages() {
        for message in [
            ToChild::Secrets,
            ToChild::PeerRpc { request_id: 1 },
            ToChild::FindingAppend { request_id: 1 },
            ToChild::Wake {
                reason: WakeReason::DataArrival,
            },
            ToChild::NativeRun {
                service: NativeChildService::LandingBytesV1,
            },
        ] {
            let fd = fdpass::secret_memfd(b"synthetic-never-native").unwrap();
            assert_eq!(
                decode_event(message, vec![fd], true).err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(decode_event(ToChild::Rpc { request_id: 1 }, vec![], true).is_err());
        // H02 CP35 P2-1: a parts service (one fd: its part channel) refuses
        // any per-request stream, even a valid connected unix stream.
        let (_peer, parts_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            decode_event(ToChild::Rpc { request_id: 2 }, vec![parts_stream.into()], false).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(decode_event(ToChild::Shutdown { grace_ms: 1 }, vec![], false).is_ok(), "shutdown still reaches parts");
        assert!(decode_event(
            ToChild::Rpc { request_id: 1 },
            vec![fdpass::secret_memfd(b"synthetic").unwrap()],
            true
        )
        .is_err());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _peer = listener.accept().unwrap();
        assert!(
            decode_event(ToChild::Rpc { request_id: 1 }, vec![stream.into()], true).is_err(),
            "TCP is not a native byte-channel fd"
        );
        let dir = tempfile::tempdir().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(dir.path().join("listener")).unwrap();
        assert!(
            decode_event(ToChild::Rpc { request_id: 1 }, vec![listener.into()], true).is_err(),
            "listening socket is not a connected byte channel"
        );
    }
}
