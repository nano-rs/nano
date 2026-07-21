-- NAN-1977: shared artifact-analysis reports (nano Desktop "Artifacts" pane persistence).
--
-- Stores the analysis REPORT, not the file. The specimen is kept as text
-- (`original`) — binaries are already reduced to printable strings upstream, so
-- no raw bytes are ever persisted and the SIEM never becomes a malware
-- repository. The store is SHARED: every holder of `artifacts:view` sees the
-- whole collection (a shared evidence locker), consistent with how pivt sessions
-- are already server-side. A deployment is the tenant, so there is no tenant
-- column — authorship is captured by `created_by`.
--
-- IMPORTANT (open-core): this is a CORE migration and runs on every edition.
-- `case_id` is a bare UUID SOFT LINK with deliberately NO foreign key: the table
-- it would reference is enterprise-only and absent from the open snapshot, so a
-- real FK here would break fresh open installs at boot (the NAN-1265/1502/1757
-- failure class). The link is resolved in the application layer when present.

CREATE TABLE IF NOT EXISTS public.artifacts (
    id            uuid PRIMARY KEY DEFAULT public.uuid_generate_v4(),
    name          text NOT NULL,
    sha256        text NOT NULL DEFAULT '',       -- lowercase hex; '' while the async hash computes
    size_bytes    bigint NOT NULL DEFAULT 0,
    source        text NOT NULL DEFAULT '',
    verdict       text NOT NULL DEFAULT 'queued', -- malicious|suspicious|analyzing|queued|clean (app-validated)
    score         double precision,
    original      text NOT NULL,                  -- specimen text (printable strings for binaries); app byte-capped
    deobfuscated  text,
    passes        jsonb NOT NULL DEFAULT '[]'::jsonb,
    iocs          jsonb NOT NULL DEFAULT '[]'::jsonb,
    mitre         jsonb NOT NULL DEFAULT '[]'::jsonb,
    behavior      text,
    layer_chain   text,
    agent_note    text,
    entropy       double precision,
    summary       text,
    status_line   text,
    case_tag      text,                           -- human display label ("case-1043"), NOT an id
    correlation   text,
    analysis_secs double precision,
    engine        text,                           -- analysis engine (claude/codex/agy), if known
    case_id       uuid,                           -- optional soft link to an investigation (no FK; see header)
    created_by    uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Newest-first is the list default (shared locker ordered by arrival).
CREATE INDEX IF NOT EXISTS idx_artifacts_created_at ON public.artifacts (created_at DESC);
-- Sighting lookups by hash and authorship filters.
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256     ON public.artifacts (sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_created_by ON public.artifacts (created_by);
-- Partial index for the (optional) investigation link.
CREATE INDEX IF NOT EXISTS idx_artifacts_case_id    ON public.artifacts (case_id) WHERE case_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Permissions (RBAC-scoped like every other resource). The 001 blanket
-- "Admin gets everything" grant already ran at seed time, so a permission added
-- by a later migration must grant itself to Admin explicitly (250 precedent).
-- ---------------------------------------------------------------------------
INSERT INTO public.permissions (id, name, description, category) VALUES
    ('artifacts:view',   'View Artifacts',   'View the shared artifact-analysis collection', 'artifacts'),
    ('artifacts:create', 'Create Artifacts', 'Add specimens to the artifact-analysis collection', 'artifacts'),
    ('artifacts:edit',   'Edit Artifacts',   'Write analysis results back onto an artifact', 'artifacts'),
    ('artifacts:delete', 'Delete Artifacts', 'Remove artifacts from the collection', 'artifacts')
ON CONFLICT (id) DO NOTHING;

-- Admin (…0001): all four.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', p.id
FROM public.permissions p
WHERE p.id IN ('artifacts:view', 'artifacts:create', 'artifacts:edit', 'artifacts:delete')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Editor (…0002): full analyst workflow (view + create + edit + delete) — artifact
-- analysis is ordinary analyst work, matching the notebooks/detections precedent.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', p.id
FROM public.permissions p
WHERE p.id IN ('artifacts:view', 'artifacts:create', 'artifacts:edit', 'artifacts:delete')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ReadOnly (…0003): view only.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', p.id
FROM public.permissions p
WHERE p.id IN ('artifacts:view')
ON CONFLICT (role_id, permission_id) DO NOTHING;
