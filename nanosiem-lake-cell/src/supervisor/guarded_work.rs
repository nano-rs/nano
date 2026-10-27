// SPDX-License-Identifier: AGPL-3.0-or-later
//! Current-process currency only. This is NOT conversion/output evidence.
use super::*;

/// An exact owned landing (or, H02 B2, native ingest/query) process, never a
/// caller pid or serialized receipt. H02 separately binds its originating
/// supervisor to a verified native plan.
pub struct GuardedNativeWorker {
    owner: Arc<Supervisor>,
    process: Arc<Proc>,
    _inflight: InflightGuard,
    invalid: AtomicBool,
}

/// The original Landing-only name; the same guarded handle.
pub type GuardedLandingWorker = GuardedNativeWorker;

fn denied() -> CellError {
    CellError::Unavailable("guarded landing worker is unavailable".into())
}

/// Cancellation after acquiring a process is uncertain work. Stop precisely
/// that process synchronously, even if no Tokio runtime remains during Drop.
struct Checking<'a> {
    worker: &'a GuardedNativeWorker,
    complete: bool,
}
impl Drop for Checking<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.worker.abort();
        }
    }
}

impl GuardedNativeWorker {
    /// Factual process identity; it authenticates neither program nor output.
    pub fn process_identity(&self) -> (u32, u64) {
        (self.process.pid, self.process.starttime)
    }

    /// Permanently invalidate this handle and kill exactly its process.
    /// Synchronous, so it is safe from Drop after cancellation.
    pub fn abort(&self) {
        self.invalid.store(true, Ordering::SeqCst);
        let _permit = self.owner.secret_delivery.lock().unwrap();
        self.process.stopping.store(true, Ordering::SeqCst);
        self.process.kill("guarded_landing_check_refused");
    }

    /// Open ONE connected AF_UNIX byte stream to this exact native
    /// LandingBytesV1 process: a fixed `Rpc` frame with one fd, sent under the
    /// delivery gate after the local currency check. No endpoint, command,
    /// tenant or credential is accepted. Legacy processes are refused. Any
    /// failure kills the process. The stream is transport only; the caller
    /// re-checks currency after the exchange.
    pub async fn open_native_stream(&self) -> Result<(u64, tokio::net::UnixStream), CellError> {
        let mut check = Checking {
            worker: self,
            complete: false,
        };
        if self.process.native != Some(NativeChildService::LandingBytesV1) {
            // Not a native Landing byte process (parts services hold exactly
            // one fd, their part channel): refuse without touching it.
            check.complete = true;
            return Err(denied());
        }
        self.local_current()?;
        let (ours, theirs) = fdpass::stream_pair().map_err(|_| denied())?;
        let id = self.process.next_request.fetch_add(1, Ordering::Relaxed);
        let frame = ToChild::Rpc { request_id: id };
        let fds = [theirs.as_fd()];
        let send = self.process.control.send_json_guarded(
            &frame,
            &fds,
            &self.owner.secret_delivery,
            || {
                if self.invalid.load(Ordering::SeqCst)
                    || self.process.stopping.load(Ordering::SeqCst)
                    || self.process.exited.load(Ordering::SeqCst)
                    || self.process.pidfd.exited()
                    || self.owner.stopping_all.load(Ordering::SeqCst)
                    || self.owner.is_halted()
                    || self.owner.draining()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "native landing stopped before rpc",
                    ));
                }
                Ok(())
            },
        );
        tokio::time::timeout(Duration::from_secs(5), send)
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
        drop(fds);
        drop(theirs);
        let std = std::os::unix::net::UnixStream::from(ours);
        std.set_nonblocking(true).map_err(|_| denied())?;
        let stream = tokio::net::UnixStream::from_std(std).map_err(|_| denied())?;
        check.complete = true;
        Ok((id, stream))
    }

    /// H02 B2: the supervisor end of this exact native ingest/query
    /// process's one part channel, after the local currency check. Frames
    /// are opaque here; the composition serving them re-checks
    /// [`Self::confirm_current`] around each effect. Landing and legacy
    /// processes have none.
    pub fn part_channel(&self) -> Result<Arc<crate::part_channel::PartChannel>, CellError> {
        self.local_current()?;
        self.process.part_channel.clone().ok_or_else(denied)
    }

    /// H02 B2 (pE amendment b, PutSpool): the supervisor's path of this exact
    /// native INGEST process's one rw root, the same directory the child's
    /// assignment grants it (`<data_dir>/tenants/<T>/ingest`). The caller
    /// opens spool files beneath it without following links and re-checks
    /// [`Self::confirm_current`] before publishing. Query (scratch only) and
    /// non-native processes have none.
    pub fn tenant_rw_root(&self) -> Result<std::path::PathBuf, CellError> {
        self.local_current()?;
        if self.process.role != Role::Ingest || self.process.part_channel.is_none() {
            return Err(denied());
        }
        Ok(native_rw_root(&self.owner.cfg.data_dir, &self.process.tenant, Role::Ingest))
    }

    fn local_current(&self) -> Result<(), CellError> {
        if self.invalid.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let _permit = self.owner.installation_live_permit()?;
        let role = self.process.role;
        let placed = self.owner.placed(&self.process.tenant);
        let wanted = match role {
            Role::Landing => landing_wanted(self.owner.cfg.tenzir_landing, placed.as_ref()),
            // H02 B2: native ingest/query serve a placed tenant only.
            Role::Ingest | Role::Query => placed.is_some() && self.process.native.is_some_and(|s| s.role() == role),
            _ => false,
        };
        if self.owner.installation_policy.is_none()
            || self.process.stopping.load(Ordering::SeqCst)
            || self.process.exited.load(Ordering::SeqCst)
            || self.process.pidfd.exited()
            || !wanted
        {
            return Err(denied());
        }
        let owned = self
            .owner
            .tenants
            .lock()
            .unwrap()
            .get(&self.process.tenant)
            .cloned()
            .ok_or_else(denied)?;
        let processes = owned.procs.lock().unwrap();
        if !processes[role_idx(role)]
            .as_ref()
            .is_some_and(|p| Arc::ptr_eq(p, &self.process))
        {
            return Err(denied());
        }
        Ok(())
    }

    /// Re-run the production C04 C01/C03, boot/runtime and child-jail hooks on
    /// this retained pidfd/start identity. No key is minted or delivered here.
    /// A successful check is an observation, not a permit for a later effect.
    pub async fn confirm_current(&self) -> Result<(), CellError> {
        let mut check = Checking {
            worker: self,
            complete: false,
        };
        self.local_current()?;
        let p = &self.process;
        let policy = self.owner.installation_policy.as_ref().ok_or_else(denied)?;
        let child = crate::policy::ChildIdentity {
            stage: crate::policy::SecretStage::Refresh,
            pid: p.pid,
            pidfd: p.pidfd.as_fd(),
            spawn_start_time_ticks: p.starttime,
            jail_completed: p.jail_completed,
            cgroup_namespace: p.cgroup_namespace,
        };
        // Existing-child checks allow worker threads, as secret refresh does.
        tokio::time::timeout(
            Duration::from_secs(5),
            policy.before_secrets(&p.tenant, p.role, &p.jail, child),
        )
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
        self.local_current()?;
        check.complete = true;
        Ok(())
    }
}

impl Supervisor {
    /// Captures an existing guarded landing process only. It never spawns a
    /// worker, exchanges credentials or changes placement. Unknown bootstrap
    /// and the future byte-only converter endpoint stay outside this reader.
    pub async fn current_guarded_landing(
        self: &Arc<Self>,
        tenant: &TenantId,
    ) -> Result<GuardedNativeWorker, CellError> {
        self.current_guarded_role(tenant, Role::Landing).await
    }

    /// H02 B2: an existing guarded NATIVE ingest/query process (the same
    /// capture as [`Self::current_guarded_landing`]). Legacy processes of
    /// those roles are refused.
    pub async fn current_guarded_native(
        self: &Arc<Self>,
        tenant: &TenantId,
        role: Role,
    ) -> Result<GuardedNativeWorker, CellError> {
        if !matches!(role, Role::Ingest | Role::Query) {
            return Err(denied());
        }
        self.current_guarded_role(tenant, role).await
    }

    async fn current_guarded_role(
        self: &Arc<Self>,
        tenant: &TenantId,
        role: Role,
    ) -> Result<GuardedNativeWorker, CellError> {
        let process = {
            let _permit = self.installation_live_permit()?;
            if self.installation_policy.is_none() {
                return Err(denied());
            }
            let owned = self
                .tenants
                .lock()
                .unwrap()
                .get(tenant)
                .cloned()
                .ok_or_else(denied)?;
            let process = owned.procs.lock().unwrap()[role_idx(role)]
                .clone()
                .ok_or_else(denied)?;
            if role != Role::Landing && process.native.is_none() {
                return Err(denied());
            }
            process
        };
        let worker = GuardedNativeWorker {
            _inflight: process.begin_request(),
            owner: self.clone(),
            process,
            invalid: AtomicBool::new(false),
        };
        worker.confirm_current().await?;
        Ok(worker)
    }
}
