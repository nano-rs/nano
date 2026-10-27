// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installation-owned policy; never selected by tenant input or cell JSON.
use crate::config::{CellConfig, Placement};
use crate::contract::{JailSpec, NativeChildService, Role, TenantId};
use async_trait::async_trait;
use std::os::fd::BorrowedFd;
use zeroize::Zeroizing;

/// Lifecycle context comes only from supervisor handshake/control-reader code.
/// It cannot be selected in a tenant request or cell configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretStage {
    Assignment,
    Refresh,
}

/// The same live process identity on every guard, including secret refresh.
#[derive(Clone, Copy)]
pub struct ChildIdentity<'a> {
    pub stage: SecretStage,
    pub pid: u32,
    pub pidfd: BorrowedFd<'a>,
    pub spawn_start_time_ticks: u64,
    /// Immutable image bootstrap's completed jail, bound to this pidfd/start.
    /// Landlock cannot be remotely queried on supported kernels; its
    /// irreversible installation is corroborated by inside-jail V probes.
    pub jail_completed: bool,
    pub cgroup_namespace: bool,
}

#[async_trait]
pub trait SupervisorPolicy: Send + Sync {
    async fn preflight(&self, config: &CellConfig) -> anyhow::Result<()>;
    async fn placement(&self, config: &CellConfig, placement: &Placement) -> anyhow::Result<()>;
    /// Re-resolve async authority and inspect the spawned process, not its message.
    async fn before_secrets(
        &self,
        tenant: &TenantId,
        role: Role,
        jail: &JailSpec,
        child: ChildIdentity<'_>,
    ) -> anyhow::Result<()>;
    /// Expected native byte service for `role`, projected ONLY from an
    /// installation's immutable verified package plan. It is compatibility
    /// data, never current authorization: every native start still passes
    /// [`guarded_native_start`]. Default `None` keeps the legacy flow.
    fn native_service(&self, _role: Role) -> Option<NativeChildService> {
        None
    }
}

/// The credential-free native counterpart of [`guarded_mint`]: the same
/// async current child/authority guard, bounded, with no mint between. The
/// caller then sends `NativeRun` under its local delivery gate, or kills the
/// exact child on any error.
pub async fn guarded_native_start(
    policy: &dyn SupervisorPolicy,
    tenant: &TenantId,
    role: Role,
    jail: &JailSpec,
    child: ChildIdentity<'_>,
    deadline: std::time::Duration,
) -> anyhow::Result<NativeChildService> {
    let service = policy
        .native_service(role)
        .filter(|service| native_service_allowed(role, *service))
        .ok_or_else(|| anyhow::anyhow!("native service is not selected for this role"))?;
    let child = ChildIdentity {
        stage: SecretStage::Assignment,
        ..child
    };
    tokio::time::timeout(deadline, policy.before_secrets(tenant, role, jail, child))
        .await
        .map_err(|_| anyhow::anyhow!("native start guard deadline"))??;
    Ok(service)
}

/// The only legal native selections: each service serves exactly its role
/// (Landing: LandingBytesV1; H02 B2 Ingest: IngestPartsV1, Query: QueryPartsV1).
pub fn native_service_allowed(role: Role, service: NativeChildService) -> bool {
    service.role() == role
}

/// Neither assignment nor refresh polls mint before the initial guard. Both
/// recheck authority and the same child after the await, before secret exposure.
pub async fn guarded_mint(
    policy: Option<&dyn SupervisorPolicy>,
    tenant: &TenantId,
    role: Role,
    jail: &JailSpec,
    child: ChildIdentity<'_>,
    mint: impl std::future::Future<Output = anyhow::Result<Zeroizing<Vec<u8>>>>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if let Some(policy) = policy {
        policy.before_secrets(tenant, role, jail, child).await?;
    }
    let secret = mint.await?;
    if let Some(policy) = policy {
        policy.before_secrets(tenant, role, jail, child).await?;
    }
    Ok(secret)
}

/// Only provider and transport IO is replaceable in refresh-path tests.
#[async_trait]
pub trait SecretRefresh: Send + Sync {
    async fn mint(&self) -> anyhow::Result<Zeroizing<Vec<u8>>>;
    async fn deliver(&self, secret: &[u8]) -> anyhow::Result<()>;
    fn stop(&self);
    /// The actual process's immutable native service, if any. A native byte
    /// service has no credential: refresh is refused and the child stopped.
    fn native(&self) -> Option<NativeChildService> {
        None
    }
}

/// Used by both immediate RefreshSecrets and its paced/deferred response.
/// A sovereign refusal stops the child; legacy callers retain retry behavior.
pub async fn send_fresh_secret(
    policy: Option<&dyn SupervisorPolicy>,
    tenant: &TenantId,
    role: Role,
    jail: &JailSpec,
    child: ChildIdentity<'_>,
    io: &dyn SecretRefresh,
) -> anyhow::Result<()> {
    if io.native().is_some() {
        // Before any guard/mint await: zero KeySource or delivery effects.
        io.stop();
        anyhow::bail!("native byte service has no credential refresh");
    }
    let child = ChildIdentity {
        stage: SecretStage::Refresh,
        ..child
    };
    let result = async {
        let secret = guarded_mint(policy, tenant, role, jail, child, io.mint()).await?;
        io.deliver(&secret).await
    }
    .await;
    if result.is_err() && policy.is_some() {
        io.stop();
    }
    result
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        native: Option<NativeChildService>,
        guards: AtomicUsize,
        hang: bool,
        deny: bool,
    }
    #[async_trait]
    impl SupervisorPolicy for Counting {
        async fn preflight(&self, _: &CellConfig) -> anyhow::Result<()> {
            Ok(())
        }
        async fn placement(&self, _: &CellConfig, _: &Placement) -> anyhow::Result<()> {
            Ok(())
        }
        async fn before_secrets(
            &self,
            _: &TenantId,
            _: Role,
            _: &JailSpec,
            child: ChildIdentity<'_>,
        ) -> anyhow::Result<()> {
            assert!(child.stage == SecretStage::Assignment);
            self.guards.fetch_add(1, Ordering::SeqCst);
            if self.hang {
                std::future::pending::<()>().await;
            }
            anyhow::ensure!(!self.deny, "synthetic denial");
            Ok(())
        }
        fn native_service(&self, _: Role) -> Option<NativeChildService> {
            self.native
        }
    }
    #[derive(Default)]
    struct Io {
        native: Option<NativeChildService>,
        mints: AtomicUsize,
        delivered: AtomicUsize,
        stops: AtomicUsize,
    }
    #[async_trait]
    impl SecretRefresh for Io {
        async fn mint(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
            self.mints.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(b"synthetic".to_vec()))
        }
        async fn deliver(&self, _: &[u8]) -> anyhow::Result<()> {
            self.delivered.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn stop(&self) {
            self.stops.fetch_add(1, Ordering::SeqCst);
        }
        fn native(&self) -> Option<NativeChildService> {
            self.native
        }
    }
    fn jail() -> JailSpec {
        JailSpec {
            uid: 20020,
            gid: 20000,
            rw_paths: vec![],
            ro_paths: vec![],
            system_ro_paths: vec![],
            tcp_connect_ports: vec![],
            cgroup_dir: None,
            require_landlock: true,
            max_processes: Some(64),
            max_open_files: 64,
        }
    }
    fn child(fd: &std::fs::File) -> ChildIdentity<'_> {
        use std::os::fd::AsFd;
        ChildIdentity {
            stage: SecretStage::Refresh,
            pid: 7,
            pidfd: fd.as_fd(),
            spawn_start_time_ticks: 9,
            jail_completed: true,
            cgroup_namespace: true,
        }
    }

    #[tokio::test]
    async fn native_refresh_is_refused_before_any_guard_mint_or_delivery() {
        let fd = std::fs::File::open("/dev/null").unwrap();
        let tenant = TenantId::new("tenant-a").unwrap();
        for with_policy in [false, true] {
            let policy = Counting::default();
            let io = Io {
                native: Some(NativeChildService::LandingBytesV1),
                ..Io::default()
            };
            let policy_ref: Option<&dyn SupervisorPolicy> = with_policy.then_some(&policy);
            assert!(send_fresh_secret(
                policy_ref,
                &tenant,
                Role::Landing,
                &jail(),
                child(&fd),
                &io
            )
            .await
            .is_err());
            assert_eq!(io.mints.load(Ordering::SeqCst), 0, "zero KeySource mint");
            assert_eq!(
                io.delivered.load(Ordering::SeqCst),
                0,
                "zero memfd delivery"
            );
            assert_eq!(
                io.stops.load(Ordering::SeqCst),
                1,
                "exact child stopped even without a policy"
            );
            assert_eq!(policy.guards.load(Ordering::SeqCst), 0);
        }
        // Legacy refresh behavior is unchanged: mint and deliver once.
        let io = Io::default();
        send_fresh_secret(None, &tenant, Role::Ingest, &jail(), child(&fd), &io)
            .await
            .unwrap();
        assert_eq!(
            (
                io.mints.load(Ordering::SeqCst),
                io.delivered.load(Ordering::SeqCst),
                io.stops.load(Ordering::SeqCst)
            ),
            (1, 1, 0)
        );
    }

    #[tokio::test]
    async fn native_start_requires_projection_and_one_bounded_assignment_guard() {
        let fd = std::fs::File::open("/dev/null").unwrap();
        let tenant = TenantId::new("tenant-a").unwrap();
        let deadline = std::time::Duration::from_millis(200);
        let start = |p: &'static Counting, role| {
            let fd = &fd;
            let tenant = &tenant;
            async move { guarded_native_start(p, tenant, role, &jail(), child(fd), deadline).await }
        };
        let none: &'static Counting = Box::leak(Box::default());
        assert!(
            start(none, Role::Landing).await.is_err(),
            "no projection: no native start"
        );
        assert_eq!(none.guards.load(Ordering::SeqCst), 0);
        let native: &'static Counting = Box::leak(Box::new(Counting {
            native: Some(NativeChildService::LandingBytesV1),
            ..Counting::default()
        }));
        assert!(
            start(native, Role::Ingest).await.is_err(),
            "only Landing serves LandingBytesV1"
        );
        assert_eq!(native.guards.load(Ordering::SeqCst), 0);
        assert_eq!(
            start(native, Role::Landing).await.unwrap(),
            NativeChildService::LandingBytesV1
        );
        assert_eq!(
            native.guards.load(Ordering::SeqCst),
            1,
            "Refresh stage rewritten to Assignment, one guard"
        );
        let denied: &'static Counting = Box::leak(Box::new(Counting {
            native: Some(NativeChildService::LandingBytesV1),
            deny: true,
            ..Counting::default()
        }));
        assert!(start(denied, Role::Landing).await.is_err());
        let hung: &'static Counting = Box::leak(Box::new(Counting {
            native: Some(NativeChildService::LandingBytesV1),
            hang: true,
            ..Counting::default()
        }));
        let begun = std::time::Instant::now();
        assert!(start(hung, Role::Landing).await.is_err(), "bounded guard");
        assert!(begun.elapsed() < std::time::Duration::from_secs(5));
    }
}
