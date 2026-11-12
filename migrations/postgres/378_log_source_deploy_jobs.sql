-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5132: log-source deploys run as background jobs.
--
-- A deploy, undeploy, publish or deploy-all runs in a detached task, so a
-- client or edge disconnect can no longer stop it between promotion and
-- reload. The job row is what a client polls. It lives in PostgreSQL, not in
-- process memory, so any app host can answer a poll (Compose HA, k8s).
--
-- `coalesce_key` + the partial unique index: at most one coalescible job per
-- target is waiting for the deploy lock. A second async request for the same
-- target joins that job instead of queueing another full render.
--
-- `heartbeat_at`: the owning process refreshes it while the job runs. A
-- non-terminal job whose heartbeat stopped belongs to a process that died; it
-- is reported `interrupted`.
--
-- TypeId prefix "djob" at serde layer.
CREATE TABLE IF NOT EXISTS public.log_source_deploy_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            TEXT NOT NULL
        CHECK (kind IN ('deploy', 'undeploy', 'publish', 'deploy_all')),
    log_source_id   UUID REFERENCES public.log_sources(id) ON DELETE SET NULL,
    coalesce_key    TEXT NOT NULL,
    coalescible     BOOLEAN NOT NULL DEFAULT FALSE,
    state           TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'rolled_back', 'interrupted')),
    phase           TEXT NOT NULL DEFAULT 'queued',
    message         TEXT,
    result          JSONB,
    error_status    SMALLINT,
    requested_by    UUID,
    owner_instance  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    heartbeat_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS log_source_deploy_jobs_one_queued
    ON public.log_source_deploy_jobs (coalesce_key)
    WHERE state = 'queued' AND coalescible;

CREATE INDEX IF NOT EXISTS log_source_deploy_jobs_source_recent
    ON public.log_source_deploy_jobs (log_source_id, created_at DESC);

CREATE INDEX IF NOT EXISTS log_source_deploy_jobs_active
    ON public.log_source_deploy_jobs (heartbeat_at)
    WHERE state IN ('queued', 'running');
